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

	"github.com/AbnerEarl/HostCollision/pkg/collision"
	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/helpers"
	"github.com/AbnerEarl/HostCollision/pkg/httpclient"
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
	MatchContentLen        int    // 碰撞请求的响应大小
	BaseContentLen         int    // 基准请求的响应大小
	ErrorHostContentLen    int    // 绝对错误请求的响应大小
	RelativeHostContentLen int    // 相对错误请求的响应大小
	MatchStatusCode        int    // 碰撞请求的状态码
	BaseStatusCode         int    // 基准请求的状态码
	ErrorHostStatusCode    int    // 绝对错误请求的状态码
	RelativeHostStatusCode int    // 相对错误请求的状态码
}

// String 返回结果的可读字符串
func (r *Result) String() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode)
}

// DefaultOptions 返回一套合理的默认配置选项
func DefaultOptions() *Options {
	return &Options{
		Protocols:                  []string{"http://", "https://"},
		Threads:                    6,
		OutputErrorLog:             false,
		CollisionSuccessStatusCode: "200,301,302,404",
		DataSampleNumber:           10,
		SimilarityRatio:            0.7,
		RateLimit:                  50,
		DelayMin:                   1000,
		DelayMax:                   3000,
		RandomUA:                   true,
		FakeHeaders:                true,
		FakeHeadersMap: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
			"X-Client-IP":      "127.0.0.1",
			"CF-Connecting-IP": "127.0.0.1",
		},
		ReadTimeout:      10,
		ConnectTimeout:   10,
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

	// 请求计数器
	var numOfRequest int64

	// 碰撞成功结果列表（内部类型）
	var internalResults []*collision.CollisionResult
	var resultsMu sync.Mutex

	// 总任务数
	requestTotal := int64(len(ipList) * len(opts.Protocols) * len(hostList))

	// IP 数据分块
	ipChunks := helpers.ListChunkSplit(ipList, threads)

	// 建立 goroutine 池
	var wg sync.WaitGroup
	for _, chunk := range ipChunks {
		wg.Add(1)
		worker := collision.NewWorker(
			cfg,
			&numOfRequest,
			&internalResults,
			&resultsMu,
			opts.Protocols,
			chunk,
			hostList,
			opts.OutputErrorLog,
		)
		go func() {
			defer wg.Done()
			worker.Run()
		}()
	}

	// 进度监控（如果设置了回调）
	if opts.OnProgress != nil {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		go func() {
			var oldNum int64
			for {
				select {
				case <-done:
					currentNum := atomic.LoadInt64(&numOfRequest)
					opts.OnProgress(currentNum, requestTotal)
					return
				default:
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

	var numOfRequest int64

	// 使用带回调的包装结果列表
	var internalResults []*collision.CollisionResult
	var resultsMu sync.Mutex

	requestTotal := int64(len(ipList) * len(opts.Protocols) * len(hostList))

	ipChunks := helpers.ListChunkSplit(ipList, threads)

	var wg sync.WaitGroup
	for _, chunk := range ipChunks {
		wg.Add(1)
		worker := collision.NewWorker(
			cfg,
			&numOfRequest,
			&internalResults,
			&resultsMu,
			opts.Protocols,
			chunk,
			hostList,
			opts.OutputErrorLog,
		)
		go func() {
			defer wg.Done()
			worker.Run()
		}()
	}

	// 用单独的 goroutine 监控结果并触发回调
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	callbackIndex := 0
	for {
		select {
		case <-done:
			// 处理剩余结果
			resultsMu.Lock()
			for i := callbackIndex; i < len(internalResults); i++ {
				if opts.OnResult != nil {
					opts.OnResult(internalResultToResult(internalResults[i]))
				}
			}
			resultsMu.Unlock()

			// 最终进度回调
			if opts.OnProgress != nil {
				currentNum := atomic.LoadInt64(&numOfRequest)
				opts.OnProgress(currentNum, requestTotal)
			}
			return nil

		default:
			// 实时处理新结果
			resultsMu.Lock()
			for i := callbackIndex; i < len(internalResults); i++ {
				callbackIndex++
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

	return cfg
}

// internalResultToResult 将内部碰撞结果转换为公开结果
func internalResultToResult(r *collision.CollisionResult) *Result {
	return &Result{
		Protocol:               r.Protocol,
		IP:                     r.IP,
		Host:                   r.Host,
		Title:                  r.Title,
		MatchContentLen:        r.MatchContentLen,
		BaseContentLen:         r.BaseContentLen,
		ErrorHostContentLen:    r.ErrorHostContentLen,
		RelativeHostContentLen: r.RelativeHostContentLen,
		MatchStatusCode:        r.MatchStatusCode,
		BaseStatusCode:         r.BaseStatusCode,
		ErrorHostStatusCode:    r.ErrorHostStatusCode,
		RelativeHostStatusCode: r.RelativeHostStatusCode,
	}
}
