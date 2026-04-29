// Package hostcollision 提供 Host 碰撞资产发现功能。
//
// HostCollision 通过向目标 IP 发送携带不同 Host 头的 HTTP 请求，
// 对比响应差异来发现隐藏在 CDN / 反向代理 / 负载均衡 背后的真实资产。
//
// # 快速使用
//
//	results, err := hostcollision.Run(
//	    []string{"1.2.3.4", "5.6.7.8"},
//	    []string{"admin.example.com", "api.example.com"},
//	)
//
// # 自定义配置
//
//	opts := hostcollision.DefaultOptions()
//	opts.Protocols = []string{"https://"}
//	opts.Threads = 10
//	opts.RateLimit = 30
//	results, err := hostcollision.RunWithOptions(ipList, hostList, opts)
package hostcollision

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AbnerEarl/HostCollision/pkg/collision"
	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/dnsfilter"
	"github.com/AbnerEarl/HostCollision/pkg/helpers"
	"github.com/AbnerEarl/HostCollision/pkg/httpclient"
	"github.com/AbnerEarl/HostCollision/pkg/tlsscan"
)

// Options 碰撞任务配置选项
// 所有字段都有合理的默认值，可通过 DefaultOptions() 获取
type Options struct {
	// Protocols 扫描协议列表, 可选值: "http://", "https://"
	Protocols []string

	// Threads 最大并发 goroutine 数量
	Threads int

	// OutputErrorLog 是否在控制台输出错误日志
	OutputErrorLog bool

	// CollisionSuccessStatusCode 碰撞成功的状态码白名单（逗号分隔）
	// 例如: "200,301,302,404"
	CollisionSuccessStatusCode string

	// DataSampleNumber 数据样本请求次数（0=关闭）
	DataSampleNumber int

	// SimilarityRatio 页面相似度阈值（0~1），超过此值认为是误报
	SimilarityRatio float64

	// RateLimit 每秒最大请求数（0=不限制）
	RateLimit int

	// DelayMin 延迟扫描最小间隔（毫秒），0=不延迟
	DelayMin int

	// DelayMax 延迟扫描最大间隔（毫秒），0=不延迟
	DelayMax int

	// RandomUA 是否启用 User-Agent 随机化
	RandomUA bool

	// FakeHeaders 是否启用 Header 伪造（Bypass WAF）
	FakeHeaders bool

	// FakeHeadersMap 自定义伪造 Header 键值对
	// 默认包含 X-Forwarded-For, X-Real-IP 等
	FakeHeadersMap map[string]string

	// ProxyList 代理池地址列表
	// 格式: http://ip:port, socks5://ip:port, ip:port
	ProxyList []string

	// SingleProxy 单一代理地址（与 ProxyList 互斥，ProxyList 优先）
	// 格式: http://ip:port 或 http://user:pass@ip:port
	SingleProxy string

	// ReadTimeout HTTP 读取超时（秒）
	ReadTimeout int

	// ConnectTimeout HTTP 连接超时（秒）
	ConnectTimeout int

	// ErrorHost 绝对错误的 Host 地址（用于基准比对）
	ErrorHost string

	// RelativeHostName 相对主机名前缀（用于二次比对）
	RelativeHostName string

	// Blacklists WAF 黑名单配置
	Blacklists *BlacklistsOption

	// OnResult 碰撞成功时的回调函数（可选）
	// 每发现一个碰撞成功的结果就会调用一次
	OnResult func(result *Result)

	// OnProgress 进度回调函数（可选）
	// current: 当前已处理数量, total: 总任务数量
	OnProgress func(current, total int64)

	// OnError 错误回调函数（可选）
	OnError func(protocol, ip, host, message string)

	// ========== 优化策略选项 ==========

	// EnableDNSFilter 是否启用 DNS 反向筛选（默认开启）
	// 通过 DNS 解析过滤与目标 IP 无关的 Host，大幅减少无效碰撞请求
	EnableDNSFilter *bool

	// DNSMatchMode DNS 匹配模式
	// 可选值: "16"(默认/16网段), "24"(/24网段), "exact"(精确匹配)
	DNSMatchMode string

	// DNSConcurrency DNS 解析并发数（默认100）
	DNSConcurrency int

	// EnableResponseElimination 是否启用响应快速排除（默认开启）
	// 对每个 IP 碰撞前 N 个 Host 后，如果响应全部相同则跳过该 IP 剩余 Host
	EnableResponseElimination *bool

	// ResponseSampleSize 响应快速排除的采样 Host 数量（默认50）
	// 仅当 Host 总量大于此值时才启用采样排除
	ResponseSampleSize int

	// FullScan 是否强制全量扫描（忽略所有优化策略）
	FullScan bool

	// AutoFullScanThreshold 自动全量扫描阈值
	// 当预估碰撞组合数低于此值时自动切换为全量扫描（默认720000，约200QPS下1小时可完成）
	// 设为 0 表示禁用自动全量扫描
	AutoFullScanThreshold int64

	// EnableHEADPreFilter 是否启用 HEAD 预筛选（默认开启）
	// 对每个 IP 先发送 HEAD 请求获取响应头指纹，只有指纹与基准不同的 Host 才进入 GET 碰撞
	// 如果服务不支持 HEAD 方法，会自动回退到 GET 碰撞
	EnableHEADPreFilter *bool

	// EnableTLSScan 是否启用 TLS 证书 SAN 提取（默认开启）
	// 对 HTTPS 端口做 TLS 握手，提取证书中的域名列表，标记为最高优先级
	EnableTLSScan *bool

	// TLSScanConcurrency TLS 扫描并发数（默认50）
	TLSScanConcurrency int

	// EnableFingerprintCache 是否启用基准指纹缓存快速比对（默认开启）
	// 使用 FNV hash 指纹做快速比对，只有 hash 不同时才做编辑距离计算
	EnableFingerprintCache *bool

	// EnableAdaptiveSampling 是否启用自适应分阶段采样（默认开启）
	// 分阶段逐步增加采样数量，对明显无效的 IP 更快跳过
	EnableAdaptiveSampling *bool

	// EnableCatchAllDetection 是否启用万能响应IP检测（默认开启）
	// 当一个 IP 对大量不同 Host 都碰撞成功时，判定为"万能响应"IP（默认虚拟主机/通配符配置），
	// 自动清除该 IP 的所有碰撞结果并跳过剩余 Host
	EnableCatchAllDetection *bool

	// CatchAllThreshold 万能响应IP判定阈值（默认10）
	// 当一个 IP+协议 维度碰撞成功的 Host 数量超过此值时，判定为万能响应IP
	CatchAllThreshold int

	// OnDNSFilterDone DNS 筛选完成时的回调函数（可选）
	OnDNSFilterDone func(result *DNSFilterResult)

	// OnTLSScanDone TLS 证书扫描完成时的回调函数（可选）
	OnTLSScanDone func(result *TLSScanResult)
}

// TLSScanResult TLS 证书扫描结果摘要（用于回调通知）
type TLSScanResult struct {
	ScannedCount int           // 成功扫描的 IP 数量
	FailedCount  int           // 扫描失败的 IP 数量
	CertDomains  int           // 提取到的证书域名数量
	MatchedHosts int           // 与 Host 列表匹配的域名数量
	Duration     time.Duration // 扫描耗时
}

// String 返回 TLS 扫描结果的可读字符串
func (r *TLSScanResult) String() string {
	return fmt.Sprintf(
		"TLS证书扫描: 成功%d, 失败%d, 提取域名%d, 匹配Host%d, 耗时%v",
		r.ScannedCount, r.FailedCount, r.CertDomains,
		r.MatchedHosts, r.Duration.Round(time.Millisecond),
	)
}

// DNSFilterResult DNS 筛选结果摘要（用于回调通知）
type DNSFilterResult struct {
	TotalHosts      int           // 总 Host 数
	MatchedCount    int           // 匹配目标 IP 段的 Host 数
	UnresolvedCount int           // DNS 解析失败的 Host 数
	UnmatchedCount  int           // 无关 Host 数
	EffectiveCount  int           // 有效 Host 数（Matched + Unresolved）
	FilteredCount   int           // 被过滤的 Host 数
	Duration        time.Duration // DNS 筛选耗时
}

// String 返回 DNS 筛选结果的可读字符串
func (r *DNSFilterResult) String() string {
	return fmt.Sprintf(
		"DNS筛选: 总计%d, 匹配IP段%d, 解析失败%d, 无关%d, 有效%d, 过滤%d, 耗时%v",
		r.TotalHosts, r.MatchedCount, r.UnresolvedCount, r.UnmatchedCount,
		r.EffectiveCount, r.FilteredCount, r.Duration.Round(time.Millisecond),
	)
}

// BlacklistsOption WAF 黑名单配置选项
type BlacklistsOption struct {
	// HTTPServices Server 头黑名单关键词
	HTTPServices []string
	// HTTPBodies 响应体黑名单关键词
	HTTPBodies []string
	// HTTPXPoweredBy X-Powered-By 头黑名单关键词
	HTTPXPoweredBy []string
}

// Result 碰撞成功结果
type Result struct {
	Protocol               string // 协议, 如 "http://" 或 "https://"
	IP                     string // IP 地址
	Host                   string // 碰撞成功的 Host
	Title                  string // 网页标题
	Body                   string // 响应体内容
	MatchContentLen        int    // 碰撞请求的响应大小
	BaseContentLen         int    // 基准请求的响应大小
	ErrorHostContentLen    int    // 绝对错误请求的响应大小
	RelativeHostContentLen int    // 相对错误请求的响应大小
	MatchStatusCode        int    // 碰撞请求的状态码
	BaseStatusCode         int    // 基准请求的状态码
	ErrorHostStatusCode    int    // 绝对错误请求的状态码
	RelativeHostStatusCode int    // 相对错误请求的状态码
	BodySimhash            uint64 // 响应体 SimHash 指纹（64位），用于相似内容聚合
}

// String 返回结果的可读字符串
func (r *Result) String() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode)
}

// boolPtr 返回 bool 值的指针（用于区分"未设置"和"设置为false"）
func boolPtr(b bool) *bool {
	return &b
}

// DefaultOptions 返回一套合理的默认配置选项
// 默认参数已针对大数据量场景优化，在安全性和速度之间取得平衡
func DefaultOptions() *Options {
	return &Options{
		Protocols:                  []string{"http://", "https://"},
		Threads:                    30,
		OutputErrorLog:             false,
		CollisionSuccessStatusCode: "200,301,302,404",
		DataSampleNumber:           3,
		SimilarityRatio:            0.7,
		RateLimit:                  200,
		DelayMin:                   50,
		DelayMax:                   200,
		RandomUA:                   true,
		FakeHeaders:                true,
		FakeHeadersMap: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
			"X-Client-IP":      "127.0.0.1",
			"CF-Connecting-IP": "127.0.0.1",
		},
		ReadTimeout:      8,
		ConnectTimeout:   5,
		ErrorHost:        "error.hchostjwdlh666666.com",
		RelativeHostName: "q1w2e3sr4.",
		Blacklists: &BlacklistsOption{
			HTTPServices: []string{"waf"},
			HTTPBodies: []string{
				`document.getElementById("mainFrame").src="http://batit.aliyun.com/alww.html";`,
				"服务器安全狗防护验证页面",
				"该网站暂时无法进行访问，可能由以下原因导致",
				"本网站尚未进行备案",
				"您的请求在Web服务器中没有找到对应的站点",
				"您没有将此域名或IP绑定到对应站点",
				"该访问行为触发了WAF安全策略",
			},
			HTTPXPoweredBy: []string{"waf"},
		},
		// 优化策略默认值
		EnableDNSFilter:           boolPtr(true),
		DNSMatchMode:              "24",
		DNSConcurrency:            100,
		EnableResponseElimination: boolPtr(true),
		ResponseSampleSize:        50,
		FullScan:                  false,
		AutoFullScanThreshold:     720000,
		// 方案一: HEAD 预筛选（默认开启）
		EnableHEADPreFilter: boolPtr(true),
		// 方案二: TLS 证书 SAN 提取（默认开启）
		EnableTLSScan:      boolPtr(true),
		TLSScanConcurrency: 50,
		// 方案三: 基准指纹缓存（默认开启）
		EnableFingerprintCache: boolPtr(true),
		// 方案五: 自适应分阶段采样（默认开启）
		EnableAdaptiveSampling: boolPtr(true),
		// 方案六: 万能响应IP检测（默认开启，阈值10）
		EnableCatchAllDetection: boolPtr(true),
		CatchAllThreshold:       10,
	}
}

// Run 使用默认配置执行 Host 碰撞
//
// ipList: 目标 IP 列表
// hostList: 域名列表
//
// 返回碰撞成功的结果列表和可能的错误
func Run(ipList, hostList []string) ([]*Result, error) {
	return RunWithOptions(ipList, hostList, DefaultOptions())
}

// applyOptimizations 应用优化策略，返回优化后的 hostList
// 包括: TLS 证书 SAN 提取、DNS 反向筛选、自动全量扫描判断
func applyOptimizations(ipList, hostList []string, opts *Options) []string {
	// 计算预估碰撞组合数
	totalCombinations := int64(len(ipList)) * int64(len(opts.Protocols)) * int64(len(hostList))

	// 强制全量扫描模式
	if opts.FullScan {
		fmt.Printf("[优化策略] 强制全量扫描模式, 碰撞组合数: %d\n", totalCombinations)
		return hostList
	}

	// 自动全量扫描: 数据量较小时（预估1小时内可完成），自动使用全量扫描
	threshold := opts.AutoFullScanThreshold
	if threshold <= 0 {
		threshold = 720000 // 默认阈值
	}
	if totalCombinations <= threshold {
		fmt.Printf("[优化策略] 碰撞组合数 %d ≤ 阈值 %d, 自动使用全量扫描\n",
			totalCombinations, threshold)
		return hostList
	}

	fmt.Printf("[优化策略] 碰撞组合数 %d > 阈值 %d, 启用优化策略\n",
		totalCombinations, threshold)

	// ===== 方案二: TLS 证书 SAN 提取 =====
	// 对 HTTPS 端口做 TLS 握手，提取证书中的域名列表
	// 匹配的域名标记为最高优先级（排在 Host 列表最前面）
	enableTLS := opts.EnableTLSScan == nil || *opts.EnableTLSScan
	if enableTLS {
		fmt.Println("[优化策略] TLS 证书 SAN 提取: 开始...")

		scanCfg := tlsscan.DefaultScanConfig()
		if opts.TLSScanConcurrency > 0 {
			scanCfg.Concurrency = opts.TLSScanConcurrency
		}
		scanCfg.OutputLog = opts.OutputErrorLog

		scanResult := tlsscan.ScanIPs(ipList, hostList, scanCfg)

		// 回调通知
		if opts.OnTLSScanDone != nil {
			opts.OnTLSScanDone(&TLSScanResult{
				ScannedCount: scanResult.ScannedCount,
				FailedCount:  scanResult.FailedCount,
				CertDomains:  len(scanResult.CertDomains),
				MatchedHosts: len(scanResult.MatchedHosts),
				Duration:     scanResult.Duration,
			})
		}

		fmt.Printf("[优化策略] TLS 证书 SAN 提取完成: 成功扫描 %d 个IP, "+
			"提取域名 %d, 匹配Host %d, 耗时 %v\n",
			scanResult.ScannedCount,
			len(scanResult.CertDomains),
			len(scanResult.MatchedHosts),
			scanResult.Duration.Round(time.Millisecond),
		)

		// 将匹配的 Host 排到列表最前面（最高优先级）
		if len(scanResult.MatchedHosts) > 0 {
			matchedSet := make(map[string]bool, len(scanResult.MatchedHosts))
			for _, h := range scanResult.MatchedHosts {
				matchedSet[strings.ToLower(h)] = true
			}

			// 分离匹配和未匹配的 Host
			var priorityHosts, otherHosts []string
			for _, h := range hostList {
				if matchedSet[strings.ToLower(h)] {
					priorityHosts = append(priorityHosts, h)
				} else {
					otherHosts = append(otherHosts, h)
				}
			}

			// 重组列表：匹配的在前，其他的在后
			hostList = make([]string, 0, len(priorityHosts)+len(otherHosts))
			hostList = append(hostList, priorityHosts...)
			hostList = append(hostList, otherHosts...)

			fmt.Printf("[优化策略] TLS 证书匹配: %d 个Host标记为最高优先级(P0)\n",
				len(priorityHosts))
		}
	}

	// ===== DNS 反向筛选 =====
	enableDNS := opts.EnableDNSFilter == nil || *opts.EnableDNSFilter
	if enableDNS {
		fmt.Println("[优化策略] DNS 反向筛选: 开始...")

		filterCfg := dnsfilter.DefaultFilterConfig()
		filterCfg.MatchMode = dnsfilter.ParseMatchMode(opts.DNSMatchMode)
		if opts.DNSConcurrency > 0 {
			filterCfg.Concurrency = opts.DNSConcurrency
		}
		filterCfg.OutputLog = opts.OutputErrorLog

		filterResult := dnsfilter.Filter(ipList, hostList, filterCfg)

		// 回调通知
		if opts.OnDNSFilterDone != nil {
			opts.OnDNSFilterDone(&DNSFilterResult{
				TotalHosts:      filterResult.TotalHosts,
				MatchedCount:    filterResult.MatchedCount,
				UnresolvedCount: filterResult.UnresolvedCount,
				UnmatchedCount:  filterResult.UnmatchedCount,
				EffectiveCount:  filterResult.MatchedCount + filterResult.UnresolvedCount,
				FilteredCount:   filterResult.UnmatchedCount,
				Duration:        filterResult.Duration,
			})
		}

		// 获取有效 Host（匹配 + 解析失败）
		effectiveHosts := filterResult.GetEffectiveHosts()

		fmt.Printf("[优化策略] DNS 反向筛选完成: 匹配模式 %s, "+
			"总计 %d → 有效 %d (匹配IP段 %d + 解析失败 %d), 过滤 %d, 耗时 %v\n",
			dnsfilter.MatchModeString(filterCfg.MatchMode),
			filterResult.TotalHosts,
			len(effectiveHosts),
			filterResult.MatchedCount,
			filterResult.UnresolvedCount,
			filterResult.UnmatchedCount,
			filterResult.Duration.Round(time.Millisecond),
		)

		if len(effectiveHosts) > 0 {
			hostList = effectiveHosts
		} else {
			fmt.Println("[优化策略] DNS 筛选后无有效 Host, 回退到全量扫描")
		}
	}

	return hostList
}

// RunWithOptions 使用自定义配置执行 Host 碰撞
//
// ipList: 目标 IP 列表
// hostList: 域名列表
// opts: 自定义配置选项
//
// 返回碰撞成功的结果列表和可能的错误
func RunWithOptions(ipList, hostList []string, opts *Options) ([]*Result, error) {
	if opts == nil {
		opts = DefaultOptions()
	}

	// 数据清洗
	ipList = helpers.DataCleaning(ipList)
	hostList = helpers.DataCleaning(hostList)

	if len(ipList) == 0 {
		return nil, fmt.Errorf("IP 列表为空")
	}
	if len(hostList) == 0 {
		return nil, fmt.Errorf("Host 列表为空")
	}
	if len(opts.Protocols) == 0 {
		return nil, fmt.Errorf("扫描协议列表为空")
	}

	// 将 Options 转换为内部 Config
	cfg := optionsToConfig(opts)

	// 重置全局状态（确保库模式下可以多次调用）
	config.ResetInstance()
	config.SetInstance(cfg)
	httpclient.ResetRateLimiter()
	httpclient.ResetProxyPoolManager()
	httpclient.ResetTransportPool()
	collision.ResetWAFPool()
	collision.ResetSampleCache()

	// 初始化速率限制器
	httpclient.InitRateLimiter(cfg.AntiDetection.RateLimit)

	// 初始化代理池
	if len(opts.ProxyList) > 0 {
		pm := httpclient.GetProxyPoolManager()
		pm.Load(opts.ProxyList)
	}

	// 线程数处理
	threads := opts.Threads
	if threads <= 0 {
		threads = 1
	}

	// IP 预检测：快速过滤不可达的IP，避免后续大量无效请求
	ipList = collision.PreCheckIPs(ipList, opts.Protocols, opts.OutputErrorLog)
	if len(ipList) == 0 {
		return nil, fmt.Errorf("所有IP均不可达")
	}

	// 应用优化策略（DNS 筛选 + 自动全量扫描判断）
	hostList = applyOptimizations(ipList, hostList, opts)
	if len(hostList) == 0 {
		return nil, fmt.Errorf("优化筛选后 Host 列表为空")
	}

	// 请求计数器
	var numOfRequest int64

	// 碰撞成功结果列表（内部类型）
	var internalResults []*collision.CollisionResult
	var resultsMu sync.Mutex
	resultDedup := make(map[string]struct{}) // 全局去重集合
	simhashDedup := make(map[string]uint64)  // SimHash 去重集合（同IP不同Host的相似内容聚合）

	// 总任务数
	requestTotal := int64(len(ipList) * len(opts.Protocols) * len(hostList))

	// 创建全局任务队列（替代IP分块，实现更均衡的负载分配）
	taskQueue := collision.NewTaskQueue(ipList, opts.Protocols)

	// 建立 goroutine 池（所有Worker从同一个队列竞争消费任务）
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		worker := collision.NewWorker(
			cfg,
			&numOfRequest,
			&internalResults,
			&resultsMu,
			resultDedup,
			simhashDedup,
			opts.Protocols,
			nil, // 不再分配IP列表，从队列消费
			hostList,
			opts.OutputErrorLog,
		)
		go func() {
			defer wg.Done()
			worker.RunFromQueue(taskQueue)
		}()
	}

	// 进度监控（如果设置了回调）
	if opts.OnProgress != nil {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		// 使用 ticker 替代忙等待，每500ms检查一次进度，大幅降低CPU占用
		ticker := time.NewTicker(500 * time.Millisecond)
		go func() {
			defer ticker.Stop()
			var oldNum int64
			for {
				select {
				case <-done:
					currentNum := atomic.LoadInt64(&numOfRequest)
					opts.OnProgress(currentNum, requestTotal)
					return
				case <-ticker.C:
					currentNum := atomic.LoadInt64(&numOfRequest)
					if currentNum != oldNum {
						oldNum = currentNum
						opts.OnProgress(currentNum, requestTotal)
					}
				}
			}
		}()

		<-done
	} else {
		wg.Wait()
	}

	// 实时回调处理（如果设置了 OnResult）
	// 注意：由于 Worker 内部会实时添加结果，这里在完成后统一触发
	// 如果需要实时回调，建议使用 RunWithCallback
	var results []*Result
	for _, r := range internalResults {
		// 跳过被标记为无效的结果（万能响应IP检测）
		if r.Invalid {
			continue
		}
		result := internalResultToResult(r)
		results = append(results, result)
		if opts.OnResult != nil {
			opts.OnResult(result)
		}
	}

	return results, nil
}

// RunWithCallback 使用回调方式执行 Host 碰撞，每发现一个结果立即回调
//
// 与 RunWithOptions 不同，此方法会在发现碰撞成功时立即触发 OnResult 回调，
// 适用于需要实时处理结果的场景（如实时写入数据库、发送通知等）
func RunWithCallback(ipList, hostList []string, opts *Options) error {
	if opts == nil {
		opts = DefaultOptions()
	}

	// 数据清洗
	ipList = helpers.DataCleaning(ipList)
	hostList = helpers.DataCleaning(hostList)

	if len(ipList) == 0 {
		return fmt.Errorf("IP 列表为空")
	}
	if len(hostList) == 0 {
		return fmt.Errorf("Host 列表为空")
	}
	if len(opts.Protocols) == 0 {
		return fmt.Errorf("扫描协议列表为空")
	}

	// 将 Options 转换为内部 Config
	cfg := optionsToConfig(opts)

	// 重置全局状态
	config.ResetInstance()
	config.SetInstance(cfg)
	httpclient.ResetRateLimiter()
	httpclient.ResetProxyPoolManager()
	httpclient.ResetTransportPool()
	collision.ResetWAFPool()
	collision.ResetSampleCache()

	// 初始化速率限制器
	httpclient.InitRateLimiter(cfg.AntiDetection.RateLimit)

	// 初始化代理池
	if len(opts.ProxyList) > 0 {
		pm := httpclient.GetProxyPoolManager()
		pm.Load(opts.ProxyList)
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = 1
	}

	// IP 预检测
	ipList = collision.PreCheckIPs(ipList, opts.Protocols, opts.OutputErrorLog)
	if len(ipList) == 0 {
		return fmt.Errorf("所有IP均不可达")
	}

	// 应用优化策略
	hostList = applyOptimizations(ipList, hostList, opts)
	if len(hostList) == 0 {
		return fmt.Errorf("优化筛选后 Host 列表为空")
	}

	var numOfRequest int64

	// 使用带回调的包装结果列表
	var internalResults []*collision.CollisionResult
	var resultsMu sync.Mutex
	resultDedup := make(map[string]struct{}) // 全局去重集合
	simhashDedup := make(map[string]uint64)  // SimHash 去重集合

	requestTotal := int64(len(ipList) * len(opts.Protocols) * len(hostList))

	// 创建全局任务队列
	taskQueue := collision.NewTaskQueue(ipList, opts.Protocols)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		worker := collision.NewWorker(
			cfg,
			&numOfRequest,
			&internalResults,
			&resultsMu,
			resultDedup,
			simhashDedup,
			opts.Protocols,
			nil,
			hostList,
			opts.OutputErrorLog,
		)
		go func() {
			defer wg.Done()
			worker.RunFromQueue(taskQueue)
		}()
	}

	// 用单独的 goroutine 监控结果并触发回调
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// 使用 ticker 替代忙等待，每200ms检查一次新结果
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	callbackIndex := 0
	for {
		select {
		case <-done:
			// 处理剩余结果
			resultsMu.Lock()
			for i := callbackIndex; i < len(internalResults); i++ {
				// 跳过被标记为无效的结果（万能响应IP检测）
				if !internalResults[i].Invalid {
					if opts.OnResult != nil {
						opts.OnResult(internalResultToResult(internalResults[i]))
					}
				}
			}
			resultsMu.Unlock()

			// 最终进度回调
			if opts.OnProgress != nil {
				currentNum := atomic.LoadInt64(&numOfRequest)
				opts.OnProgress(currentNum, requestTotal)
			}
			return nil

		case <-ticker.C:
			// 定时处理新结果（替代忙等待的 default 分支）
			resultsMu.Lock()
			for i := callbackIndex; i < len(internalResults); i++ {
				callbackIndex++
				// 跳过被标记为无效的结果（万能响应IP检测）
				if internalResults[i].Invalid {
					continue
				}
				if opts.OnResult != nil {
					opts.OnResult(internalResultToResult(internalResults[i]))
				}
			}
			resultsMu.Unlock()

			// 进度回调
			if opts.OnProgress != nil {
				currentNum := atomic.LoadInt64(&numOfRequest)
				opts.OnProgress(currentNum, requestTotal)
			}
		}
	}
}

// ========== 便捷方法 ==========

// RunHTTPOnly 仅使用 HTTP 协议执行碰撞
func RunHTTPOnly(ipList, hostList []string) ([]*Result, error) {
	opts := DefaultOptions()
	opts.Protocols = []string{"http://"}
	return RunWithOptions(ipList, hostList, opts)
}

// RunHTTPSOnly 仅使用 HTTPS 协议执行碰撞
func RunHTTPSOnly(ipList, hostList []string) ([]*Result, error) {
	opts := DefaultOptions()
	opts.Protocols = []string{"https://"}
	return RunWithOptions(ipList, hostList, opts)
}

// RunFast 快速模式（关闭速率限制、延迟和数据样本）
func RunFast(ipList, hostList []string, threads int) ([]*Result, error) {
	opts := DefaultOptions()
	opts.Threads = threads
	opts.RateLimit = 0
	opts.DelayMin = 0
	opts.DelayMax = 0
	opts.DataSampleNumber = 0
	return RunWithOptions(ipList, hostList, opts)
}

// RunStealth 隐蔽模式（低速 + 高延迟 + 代理池）
func RunStealth(ipList, hostList []string, proxyList []string) ([]*Result, error) {
	opts := DefaultOptions()
	opts.Threads = 2
	opts.RateLimit = 10
	opts.DelayMin = 2000
	opts.DelayMax = 5000
	opts.ProxyList = proxyList
	return RunWithOptions(ipList, hostList, opts)
}

// ========== 工具方法 ==========

// LoadIPsFromFile 从文件加载 IP 列表
func LoadIPsFromFile(path string) ([]string, error) {
	data, err := helpers.GetFileData(path)
	if err != nil {
		return nil, fmt.Errorf("读取IP文件失败 %s: %w", path, err)
	}
	return helpers.DataCleaning(strings.Split(strings.TrimSpace(data), "\n")), nil
}

// LoadHostsFromFile 从文件加载 Host 列表
func LoadHostsFromFile(path string) ([]string, error) {
	data, err := helpers.GetFileData(path)
	if err != nil {
		return nil, fmt.Errorf("读取Host文件失败 %s: %w", path, err)
	}
	return helpers.DataCleaning(strings.Split(strings.TrimSpace(data), "\n")), nil
}

// LoadProxiesFromFile 从文件加载代理池列表
func LoadProxiesFromFile(path string) ([]string, error) {
	return config.LoadProxyPool(path)
}

// ========== 内部转换函数 ==========

// optionsToConfig 将公开的 Options 转换为内部 Config
func optionsToConfig(opts *Options) *config.Config {
	cfg := config.DefaultConfig()

	// HTTP 配置
	cfg.HTTP.ReadTimeout = opts.ReadTimeout
	cfg.HTTP.ConnectTimeout = opts.ConnectTimeout
	if opts.ErrorHost != "" {
		cfg.HTTP.ErrorHost = opts.ErrorHost
	}
	if opts.RelativeHostName != "" {
		cfg.HTTP.RelativeHostName = opts.RelativeHostName
	}

	// 代理配置
	if len(opts.ProxyList) > 0 {
		cfg.HTTP.ProxyPool.IsStart = true
	} else if opts.SingleProxy != "" {
		cfg.HTTP.Proxy.IsStart = true
		// 简单解析单一代理地址
		cfg.HTTP.Proxy.Host = opts.SingleProxy
	}

	// 扫描协议
	cfg.HTTP.ScanProtocol.IsScanHTTP = false
	cfg.HTTP.ScanProtocol.IsScanHTTPS = false
	for _, p := range opts.Protocols {
		if p == "http://" {
			cfg.HTTP.ScanProtocol.IsScanHTTP = true
		}
		if p == "https://" {
			cfg.HTTP.ScanProtocol.IsScanHTTPS = true
		}
	}

	// 碰撞配置
	cfg.SimilarityRatio = opts.SimilarityRatio
	cfg.ThreadTotal = opts.Threads
	cfg.CollisionSuccessStatusCode = opts.CollisionSuccessStatusCode
	cfg.DataSample.Number = opts.DataSampleNumber
	cfg.IsOutputErrorLog = opts.OutputErrorLog

	// 防检测配置
	cfg.AntiDetection.RandomUA = opts.RandomUA
	cfg.AntiDetection.RateLimit = opts.RateLimit
	cfg.AntiDetection.FakeHeaders.IsStart = opts.FakeHeaders
	if opts.FakeHeadersMap != nil {
		cfg.AntiDetection.FakeHeaders.Headers = opts.FakeHeadersMap
	}
	if opts.DelayMin > 0 || opts.DelayMax > 0 {
		cfg.AntiDetection.Delay.IsStart = true
		cfg.AntiDetection.Delay.MinMs = opts.DelayMin
		cfg.AntiDetection.Delay.MaxMs = opts.DelayMax
	} else {
		cfg.AntiDetection.Delay.IsStart = false
	}

	// 黑名单配置
	if opts.Blacklists != nil {
		if opts.Blacklists.HTTPServices != nil {
			cfg.Blacklists.HTTPServices = opts.Blacklists.HTTPServices
		}
		if opts.Blacklists.HTTPBodies != nil {
			cfg.Blacklists.HTTPBodies = opts.Blacklists.HTTPBodies
		}
		if opts.Blacklists.HTTPXPoweredBy != nil {
			cfg.Blacklists.HTTPXPoweredBy = opts.Blacklists.HTTPXPoweredBy
		}
	}

	// 优化策略配置
	if opts.EnableDNSFilter != nil {
		cfg.Optimization.EnableDNSFilter = *opts.EnableDNSFilter
	}
	if opts.DNSMatchMode != "" {
		cfg.Optimization.DNSMatchMode = opts.DNSMatchMode
	}
	if opts.DNSConcurrency > 0 {
		cfg.Optimization.DNSConcurrency = opts.DNSConcurrency
	}
	if opts.EnableResponseElimination != nil {
		cfg.Optimization.EnableResponseElimination = *opts.EnableResponseElimination
	}
	if opts.ResponseSampleSize > 0 {
		cfg.Optimization.ResponseSampleSize = opts.ResponseSampleSize
	}
	cfg.Optimization.FullScan = opts.FullScan
	if opts.AutoFullScanThreshold > 0 {
		cfg.Optimization.AutoFullScanThreshold = opts.AutoFullScanThreshold
	}
	// 方案一: HEAD 预筛选
	if opts.EnableHEADPreFilter != nil {
		cfg.Optimization.EnableHEADPreFilter = *opts.EnableHEADPreFilter
	}
	// 方案二: TLS 证书 SAN 提取
	if opts.EnableTLSScan != nil {
		cfg.Optimization.EnableTLSScan = *opts.EnableTLSScan
	}
	if opts.TLSScanConcurrency > 0 {
		cfg.Optimization.TLSScanConcurrency = opts.TLSScanConcurrency
	}
	// 方案三: 基准指纹缓存
	if opts.EnableFingerprintCache != nil {
		cfg.Optimization.EnableFingerprintCache = *opts.EnableFingerprintCache
	}
	// 方案五: 自适应分阶段采样
	if opts.EnableAdaptiveSampling != nil {
		cfg.Optimization.EnableAdaptiveSampling = *opts.EnableAdaptiveSampling
	}
	// 方案六: 万能响应IP检测
	if opts.EnableCatchAllDetection != nil {
		cfg.Optimization.EnableCatchAllDetection = *opts.EnableCatchAllDetection
	}
	if opts.CatchAllThreshold > 0 {
		cfg.Optimization.CatchAllThreshold = opts.CatchAllThreshold
	}

	return cfg
}

// internalResultToResult 将内部碰撞结果转换为公开结果
func internalResultToResult(r *collision.CollisionResult) *Result {
	return &Result{
		Protocol:               r.Protocol,
		IP:                     r.IP,
		Host:                   r.Host,
		Title:                  r.Title,
		Body:                   r.Body,
		MatchContentLen:        r.MatchContentLen,
		BaseContentLen:         r.BaseContentLen,
		ErrorHostContentLen:    r.ErrorHostContentLen,
		RelativeHostContentLen: r.RelativeHostContentLen,
		MatchStatusCode:        r.MatchStatusCode,
		BaseStatusCode:         r.BaseStatusCode,
		ErrorHostStatusCode:    r.ErrorHostStatusCode,
		RelativeHostStatusCode: r.RelativeHostStatusCode,
		BodySimhash:            r.BodySimhash,
	}
}
