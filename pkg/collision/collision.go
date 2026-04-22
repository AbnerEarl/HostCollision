package collision

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/diffpage"
	"github.com/AbnerEarl/HostCollision/pkg/httpclient"
)

// ========== WAF 自适应退避追踪器 ==========

// wafState WAF 拦截状态
type wafState int

const (
	wafStateNormal  wafState = iota // 正常状态
	wafStateWarning                 // 警告状态（偶发拦截）
	wafStateBackoff                 // 退避状态（频繁拦截，需要降速）
	wafStateBlocked                 // 封锁状态（连续大量拦截，暂停后重试）
)

// wafTracker 单个 IP+协议 维度的 WAF 拦截追踪器
// 核心思想：不因为检测到WAF就放弃，而是自适应调整请求策略
type wafTracker struct {
	mu                sync.Mutex
	consecutiveBlocks int       // 连续被拦截次数
	totalBlocks       int       // 总拦截次数
	totalRequests     int       // 总请求次数
	lastBlockTime     time.Time // 上次被拦截时间
	state             wafState  // 当前状态
	backoffUntil      time.Time // 退避截止时间
}

// wafTrackerPool 全局 WAF 追踪器池（按 IP+协议 维度）
type wafTrackerPool struct {
	mu       sync.RWMutex
	trackers map[string]*wafTracker
}

var (
	globalWAFPool *wafTrackerPool
	wafPoolOnce   sync.Once
)

func getWAFPool() *wafTrackerPool {
	wafPoolOnce.Do(func() {
		globalWAFPool = &wafTrackerPool{
			trackers: make(map[string]*wafTracker),
		}
	})
	return globalWAFPool
}

// ResetWAFPool 重置 WAF 追踪器池（库模式下多次调用时使用）
func ResetWAFPool() {
	wafPoolOnce = sync.Once{}
	globalWAFPool = nil
}

func (p *wafTrackerPool) getTracker(key string) *wafTracker {
	p.mu.RLock()
	t, ok := p.trackers[key]
	p.mu.RUnlock()
	if ok {
		return t
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok = p.trackers[key]; ok {
		return t
	}
	t = &wafTracker{state: wafStateNormal}
	p.trackers[key] = t
	return t
}

// recordSuccess 记录一次成功请求（未被WAF拦截）
func (t *wafTracker) recordSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalRequests++
	t.consecutiveBlocks = 0
	// 连续成功后逐步恢复状态
	if t.state == wafStateWarning || t.state == wafStateBackoff {
		t.state = wafStateNormal
	}
}

// recordBlock 记录一次WAF拦截，返回建议的退避时间（毫秒）
func (t *wafTracker) recordBlock() (backoffMs int, shouldGiveUp bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalRequests++
	t.totalBlocks++
	t.consecutiveBlocks++
	t.lastBlockTime = time.Now()

	// 根据连续拦截次数决定策略
	switch {
	case t.consecutiveBlocks <= 2:
		// 偶发拦截：轻微退避（1-3秒）
		t.state = wafStateWarning
		return 1000 + rand.Intn(2000), false

	case t.consecutiveBlocks <= 5:
		// 频繁拦截：指数退避（3-15秒）
		t.state = wafStateBackoff
		base := int(math.Pow(2, float64(t.consecutiveBlocks-2))) * 1000
		jitter := rand.Intn(base / 2)
		backoff := base + jitter
		if backoff > 15000 {
			backoff = 15000
		}
		t.backoffUntil = time.Now().Add(time.Duration(backoff) * time.Millisecond)
		return backoff, false

	case t.consecutiveBlocks <= 10:
		// 严重拦截：长时间退避（15-30秒）
		t.state = wafStateBlocked
		backoff := 15000 + rand.Intn(15000)
		t.backoffUntil = time.Now().Add(time.Duration(backoff) * time.Millisecond)
		return backoff, false

	default:
		// 超过10次连续拦截：判定为硬封，放弃该IP+协议
		return 0, true
	}
}

// shouldWait 检查是否需要等待退避
func (t *wafTracker) shouldWait() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state >= wafStateBackoff && time.Now().Before(t.backoffUntil) {
		return time.Until(t.backoffUntil)
	}
	return 0
}

// getState 获取当前状态
func (t *wafTracker) getState() wafState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// ========== 碰撞结果 ==========

// CollisionResult Host碰撞成功的数据
type CollisionResult struct {
	Protocol               string // 协议
	IP                     string // IP地址
	Host                   string // Host
	Title                  string // 网页标题
	MatchContentLen        int    // 匹配成功的数据包大小
	BaseContentLen         int    // 原始的数据包大小
	ErrorHostContentLen    int    // 绝对错误的数据包大小
	RelativeHostContentLen int    // 相对错误的数据包大小
	MatchStatusCode        int    // 匹配成功的状态码
	BaseStatusCode         int    // 原始的状态码
	ErrorHostStatusCode    int    // 绝对错误的状态码
	RelativeHostStatusCode int    // 相对错误的状态码
	BodySimhash            uint64 // 响应体 SimHash 指纹（64位），用于相似内容聚合
	Invalid                bool   // 是否已标记为无效（万能响应IP检测后标记）
}

// CSVHeaders CSV 表头
func CSVHeaders() []string {
	return []string{
		"协议", "ip", "host", "标题",
		"匹配成功的数据包大小", "原始的数据包大小", "绝对错误的数据包大小", "相对错误的数据包大小",
		"匹配成功的数据包状态码", "原始的数据包状态码", "绝对错误的数据包状态码", "相对错误的数据包状态码",
		"body_simhash",
	}
}

// ToCSVRecord 转换为 CSV 记录
func (r *CollisionResult) ToCSVRecord() []string {
	return []string{
		r.Protocol, r.IP, r.Host, r.Title,
		fmt.Sprintf("%d", r.MatchContentLen),
		fmt.Sprintf("%d", r.BaseContentLen),
		fmt.Sprintf("%d", r.ErrorHostContentLen),
		fmt.Sprintf("%d", r.RelativeHostContentLen),
		fmt.Sprintf("%d", r.MatchStatusCode),
		fmt.Sprintf("%d", r.BaseStatusCode),
		fmt.Sprintf("%d", r.ErrorHostStatusCode),
		fmt.Sprintf("%d", r.RelativeHostStatusCode),
		fmt.Sprintf("%d", r.BodySimhash),
	}
}

// ToTXTRecord 转换为 TXT 记录
func (r *CollisionResult) ToTXTRecord() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 匹配成功的数据包大小:%d, 状态码:%d, body_simhash:%d 匹配成功",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode, r.BodySimhash)
}

// SuccessLog 匹配成功日志
func (r *CollisionResult) SuccessLog() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 匹配成功的数据包大小:%d, 状态码:%d, body_simhash:%d 匹配成功",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode, r.BodySimhash)
}

// ========== 全局任务队列模型 ==========

// CollisionTask 碰撞任务单元（IP+协议维度）
type CollisionTask struct {
	Protocol string
	IP       string
}

// TaskQueue 全局任务队列，Worker 从中取任务，实现负载均衡
type TaskQueue struct {
	tasks chan CollisionTask
}

// NewTaskQueue 创建任务队列并填充任务
// 将所有 IP×协议 组合打散后放入队列，Worker 竞争消费
func NewTaskQueue(ipList []string, protocols []string) *TaskQueue {
	tasks := make([]CollisionTask, 0, len(ipList)*len(protocols))
	for _, ip := range ipList {
		for _, protocol := range protocols {
			tasks = append(tasks, CollisionTask{Protocol: protocol, IP: ip})
		}
	}
	// 打散任务顺序，避免多个Worker同时请求同一个IP
	rand.Shuffle(len(tasks), func(i, j int) {
		tasks[i], tasks[j] = tasks[j], tasks[i]
	})

	ch := make(chan CollisionTask, len(tasks))
	for _, t := range tasks {
		ch <- t
	}
	close(ch)

	return &TaskQueue{tasks: ch}
}

// PreCheckIPs 批量预检测IP可达性
// 快速发送一个简单请求检测IP是否可达，过滤掉不可达的IP
// 返回可达的IP列表
func PreCheckIPs(ipList []string, protocols []string, outputErrorLog bool) []string {
	type checkResult struct {
		ip        string
		reachable bool
	}

	var mu sync.Mutex
	reachableSet := make(map[string]bool)
	var wg sync.WaitGroup

	// 并发检测，但限制并发数避免瞬间大量连接
	sem := make(chan struct{}, 20)

	for _, ip := range ipList {
		for _, protocol := range protocols {
			wg.Add(1)
			sem <- struct{}{}
			go func(p, i string) {
				defer wg.Done()
				defer func() { <-sem }()

				_, err := httpclient.SendHTTPGetRequestQuick(p, i, "")
				mu.Lock()
				if err == nil {
					reachableSet[i] = true
				} else if outputErrorLog {
					fmt.Printf("info: IP预检测 %s%s 不可达,将跳过: %v\n", p, i, err)
				}
				mu.Unlock()
			}(protocol, ip)
		}
	}
	wg.Wait()

	var result []string
	for _, ip := range ipList {
		if reachableSet[ip] {
			result = append(result, ip)
		}
	}

	if outputErrorLog && len(ipList) != len(result) {
		fmt.Printf("info: IP预检测完成, %d/%d 个IP可达\n", len(result), len(ipList))
	}

	return result
}

// ========== 数据样本共享缓存 ==========

// dataSampleCache 数据样本缓存（按 IP+协议 维度共享）
// 避免多个Worker重复生成同一个IP+协议的数据样本
type dataSampleCache struct {
	mu      sync.RWMutex
	samples map[string][]*httpclient.HttpCustomRequest
}

var (
	globalSampleCache *dataSampleCache
	sampleCacheOnce   sync.Once
)

func getSampleCache() *dataSampleCache {
	sampleCacheOnce.Do(func() {
		globalSampleCache = &dataSampleCache{
			samples: make(map[string][]*httpclient.HttpCustomRequest),
		}
	})
	return globalSampleCache
}

// ResetSampleCache 重置样本缓存
func ResetSampleCache() {
	sampleCacheOnce = sync.Once{}
	globalSampleCache = nil
}

// getOrCreateSamples 获取或创建数据样本（线程安全，只生成一次）
func (c *dataSampleCache) getOrCreateSamples(key, protocol, ip, errorHost string, sampleNum int) []*httpclient.HttpCustomRequest {
	// 快速路径：读锁检查
	c.mu.RLock()
	if samples, ok := c.samples[key]; ok {
		c.mu.RUnlock()
		return samples
	}
	c.mu.RUnlock()

	// 慢路径：写锁创建
	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	if samples, ok := c.samples[key]; ok {
		return samples
	}

	var samples []*httpclient.HttpCustomRequest
	for i := 0; i < sampleNum; i++ {
		sampleReq, err := httpclient.SendHTTPGetRequest(protocol, ip, errorHost)
		if err == nil {
			samples = append(samples, sampleReq)
		}
	}
	c.samples[key] = samples
	return samples
}

// ========== 碰撞工作器 ==========

// Worker Host碰撞工作器
type Worker struct {
	cfg            *config.Config
	numOfRequest   *int64 // 原子计数器：请求数
	results        *[]*CollisionResult
	resultsMu      *sync.Mutex
	resultDedup    map[string]struct{} // 全局结果去重集合（Protocol+IP+Host 构成唯一键，由 resultsMu 保护）
	scanProtocols  []string
	ipList         []string
	hostList       []string
	outputErrorLog bool

	// 缓存字段，避免重复计算
	statusCodeWhitelist  []string // 缓存解析后的状态码白名单
	serviceBlacklists    []string // 缓存HTTP Service黑名单
	bodyBlacklists       []string // 缓存HTTP Body黑名单
	xPoweredByBlacklists []string // 缓存X-Powered-By黑名单
	cacheInitOnce        sync.Once
}

// NewWorker 创建新的碰撞工作器
// resultDedup 为全局共享的去重集合，由 resultsMu 保护，所有 Worker 共享同一个实例
func NewWorker(
	cfg *config.Config,
	numOfRequest *int64,
	results *[]*CollisionResult,
	resultsMu *sync.Mutex,
	resultDedup map[string]struct{},
	scanProtocols []string,
	ipList []string,
	hostList []string,
	outputErrorLog bool,
) *Worker {
	w := &Worker{
		cfg:            cfg,
		numOfRequest:   numOfRequest,
		results:        results,
		resultsMu:      resultsMu,
		resultDedup:    resultDedup,
		scanProtocols:  scanProtocols,
		ipList:         ipList,
		hostList:       hostList,
		outputErrorLog: outputErrorLog,
	}
	return w
}

// initCache 初始化缓存（只执行一次）
func (w *Worker) initCache() {
	w.cacheInitOnce.Do(func() {
		// 预解析状态码白名单
		w.statusCodeWhitelist = parseStatusCodes(w.cfg.CollisionSuccessStatusCode)
		// 预构建黑名单列表
		w.serviceBlacklists = w.cfg.GetHTTPServiceBlacklists()
		w.bodyBlacklists = w.cfg.GetHTTPBodyBlacklists()
		w.xPoweredByBlacklists = w.cfg.GetHTTPXPoweredByBlacklists()
	})
}

// Run 执行碰撞任务（传统模式：按分配的IP列表串行处理）
func (w *Worker) Run() {
	w.initCache()
	for _, ip := range w.ipList {
		for _, protocol := range w.scanProtocols {
			w.processIPProtocol(protocol, ip)
		}
	}
}

// RunFromQueue 从全局任务队列消费任务执行（推荐模式：负载均衡）
func (w *Worker) RunFromQueue(queue *TaskQueue) {
	w.initCache()
	for task := range queue.tasks {
		w.processIPProtocol(task.Protocol, task.IP)
	}
}

// processIPProtocol 处理单个 IP + 协议的碰撞
func (w *Worker) processIPProtocol(protocol, ip string) {
	// 获取该 IP+协议 的 WAF 追踪器
	wafKey := protocol + ip
	tracker := getWAFPool().getTracker(wafKey)

	// 基础请求
	baseRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, "")
	if err != nil {
		atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
		if w.outputErrorLog {
			fmt.Printf("error: 站点 %s 访问失败,不进行host碰撞\n", protocol+ip)
		}
		return
	}

	// WAF 预检测（软检测）：检查基准请求是否命中WAF特征
	if w.isWAFBlocked(baseRequest) {
		backoffMs, shouldGiveUp := tracker.recordBlock()
		if shouldGiveUp {
			atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
			if w.outputErrorLog {
				fmt.Printf("warning: 站点 %s 连续被WAF拦截超过阈值,放弃碰撞\n", protocol+ip)
			}
			return
		}
		if backoffMs > 0 {
			if w.outputErrorLog {
				fmt.Printf("info: 站点 %s 基准请求命中WAF特征,退避 %dms 后重试\n", protocol+ip, backoffMs)
			}
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			baseRequest, err = httpclient.SendHTTPGetRequest(protocol, ip, "")
			if err != nil {
				atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
				return
			}
			if w.isWAFBlocked(baseRequest) {
				_, shouldGiveUp2 := tracker.recordBlock()
				if shouldGiveUp2 {
					atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
					if w.outputErrorLog {
						fmt.Printf("warning: 站点 %s 重试后仍被WAF拦截,放弃碰撞\n", protocol+ip)
					}
					return
				}
				if w.outputErrorLog {
					fmt.Printf("info: 站点 %s 基准请求被WAF拦截,但仍尝试碰撞(不同Host可能有不同策略)\n", protocol+ip)
				}
			} else {
				tracker.recordSuccess()
			}
		}
	} else {
		tracker.recordSuccess()
	}

	// 绝对错误请求
	errorHostRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, w.cfg.HTTP.ErrorHost)
	if err != nil {
		atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
		if w.outputErrorLog {
			fmt.Printf("error: 站点 %s 绝对错误请求失败,不进行host碰撞\n", protocol+ip)
		}
		return
	}

	// 请求长度判断
	if ok, req := requestLengthMatching([]*httpclient.HttpCustomRequest{baseRequest, errorHostRequest}); !ok {
		atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 该请求长度为%d 有异常,不进行碰撞-1\n",
				protocol, ip, req.Host, req.ContentLen)
		}
		return
	}

	// 预计算基准请求的 BodyFormat，避免在每次碰撞中重复计算
	_ = baseRequest.BodyFormat()
	_ = errorHostRequest.BodyFormat()

	// ===== 方案三: 基准指纹缓存 =====
	// 预计算基准响应和错误响应的 FNV hash 指纹，用于快速比对
	var baseBodyHash, errorBodyHash uint64
	if w.cfg.Optimization.EnableFingerprintCache {
		baseBodyHash = fnvHash(baseRequest.BodyFormat())
		errorBodyHash = fnvHash(errorHostRequest.BodyFormat())
	}

	// 打散 Host 列表顺序
	shuffledHosts := make([]string, len(w.hostList))
	copy(shuffledHosts, w.hostList)
	rand.Shuffle(len(shuffledHosts), func(i, j int) {
		shuffledHosts[i], shuffledHosts[j] = shuffledHosts[j], shuffledHosts[i]
	})

	// ===== 方案一: HEAD 预筛选 =====
	// 对每个 IP 先发送 HEAD 请求获取基准响应头指纹，
	// 然后对每个 Host 发送 HEAD 请求，只有指纹与基准不同的 Host 才进入 GET 碰撞
	// 安全保障:
	//   1. 如果服务不支持 HEAD（返回 405/501），自动回退到全量 GET 碰撞
	//   2. 如果 HEAD 基准请求被 WAF 拦截，自动回退到全量 GET 碰撞
	//   3. HEAD 筛选后候选数量过少（<5%）时，自动回退到全量 GET 碰撞（防止漏报）
	var headFilteredHosts []string
	headFilterEnabled := false

	if w.cfg.Optimization.EnableHEADPreFilter && len(shuffledHosts) > 10 {
		headFilteredHosts, headFilterEnabled = w.headPreFilter(protocol, ip, shuffledHosts, tracker)
		if headFilterEnabled && len(headFilteredHosts) > 0 {
			if w.outputErrorLog {
				fmt.Printf("info: 站点 %s HEAD预筛选: %d → %d 个候选Host\n",
					protocol+ip, len(shuffledHosts), len(headFilteredHosts))
			}
			// HEAD 筛选后的 Host 数量过少（<5%），可能是 HEAD/GET 行为不一致，回退到全量
			minCandidates := len(shuffledHosts) / 20 // 5%
			if minCandidates < 3 {
				minCandidates = 3
			}
			if len(headFilteredHosts) < minCandidates {
				if w.outputErrorLog {
					fmt.Printf("info: 站点 %s HEAD预筛选候选数过少(%d < %d), 回退到全量GET碰撞\n",
						protocol+ip, len(headFilteredHosts), minCandidates)
				}
				headFilterEnabled = false
			} else {
				// 使用 HEAD 筛选后的候选列表
				// 跳过的 Host 计入已处理数量
				skippedCount := len(shuffledHosts) - len(headFilteredHosts)
				if skippedCount > 0 {
					atomic.AddInt64(w.numOfRequest, int64(skippedCount))
				}
				shuffledHosts = headFilteredHosts
			}
		} else if headFilterEnabled && len(headFilteredHosts) == 0 {
			// HEAD 筛选后无候选，所有 Host 指纹都相同，跳过该 IP
			atomic.AddInt64(w.numOfRequest, int64(len(shuffledHosts)))
			if w.outputErrorLog {
				fmt.Printf("info: 站点 %s HEAD预筛选: 所有Host指纹与基准相同, 跳过\n", protocol+ip)
			}
			return
		}
		// headFilterEnabled == false 表示 HEAD 不可用，回退到全量 GET
	}

	// ===== 方案五: 自适应分阶段采样排除 =====
	// 替代原有的固定采样排除，分阶段逐步增加采样数量
	// 阶段1: 采样 50 个 Host，如果全部相同 → 阶段2
	// 阶段2: 采样 200 个 Host，如果全部相同 → 阶段3
	// 阶段3: 采样 500 个 Host，如果全部相同 → 跳过该 IP
	// 任何阶段发现不同响应 → 立即进入完整碰撞
	// 注意: WAF 拦截的响应不计入指纹比对（避免 WAF 干扰判断）
	sampleSize := w.cfg.Optimization.ResponseSampleSize
	enableElimination := w.cfg.Optimization.EnableResponseElimination && sampleSize > 0 && len(shuffledHosts) > sampleSize

	if enableElimination {
		var skipIP bool
		if w.cfg.Optimization.EnableAdaptiveSampling {
			skipIP = w.adaptiveSamplingElimination(protocol, ip, shuffledHosts, sampleSize, tracker)
		} else {
			skipIP = w.fixedSamplingElimination(protocol, ip, shuffledHosts, sampleSize, tracker)
		}
		if skipIP {
			return
		}

		// 采样中发现了不同响应，需要对所有 Host（包括已采样的）做完整碰撞
		// 重新打散列表，从头开始碰撞
		rand.Shuffle(len(shuffledHosts), func(i, j int) {
			shuffledHosts[i], shuffledHosts[j] = shuffledHosts[j], shuffledHosts[i]
		})
	}

	// ===== 方案六: 万能响应IP检测 =====
	// 实时统计碰撞成功数量，超过阈值时判定为"万能响应"IP
	catchAllEnabled := w.cfg.Optimization.EnableCatchAllDetection
	catchAllThreshold := w.cfg.Optimization.CatchAllThreshold
	if catchAllThreshold <= 0 {
		catchAllThreshold = 10 // 默认阈值
	}
	var ipSuccessCount int // 当前 IP+协议 的碰撞成功计数
	var isCatchAll bool    // 是否已判定为万能响应IP

	// 重试队列
	var retryQueue []string

	for idx, host := range shuffledHosts {
		atomic.AddInt64(w.numOfRequest, 1)

		// 检查是否需要等待退避
		if waitDur := tracker.shouldWait(); waitDur > 0 {
			time.Sleep(waitDur)
		}

		result := w.collision(wafKey, baseRequest, errorHostRequest, protocol, ip, host, tracker, baseBodyHash, errorBodyHash)
		if result == collisionResultWAFBlocked {
			retryQueue = append(retryQueue, host)
		}

		// 万能响应IP检测：统计碰撞成功数量
		if catchAllEnabled && result == collisionResultSuccess {
			ipSuccessCount++

			if ipSuccessCount >= catchAllThreshold {
				isCatchAll = true
				// 回溯清除该 IP 的所有碰撞结果
				removed := w.removeCatchAllResults(protocol, ip)
				// 跳过剩余 Host（idx+1 是已遍历的数量，已通过循环内 atomic.Add 计数）
				remainingCount := len(shuffledHosts) - (idx + 1)
				if remainingCount > 0 {
					atomic.AddInt64(w.numOfRequest, int64(remainingCount))
				}
				fmt.Printf("[万能响应IP检测] 协议:%s, IP:%s 碰撞成功 %d 个Host(阈值%d), 判定为万能响应IP, 已清除 %d 条结果, 跳过剩余 %d 个Host\n",
					protocol, ip, ipSuccessCount, catchAllThreshold, removed, remainingCount)
				break
			}
		}
	}

	// 如果已判定为万能响应IP，跳过重试队列
	if isCatchAll {
		return
	}

	// 处理重试队列
	if len(retryQueue) > 0 && tracker.getState() != wafStateBlocked {
		retryDelay := 5000 + rand.Intn(10000)
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s 有 %d 个Host被WAF拦截,等待 %dms 后重试\n",
				protocol+ip, len(retryQueue), retryDelay)
		}
		time.Sleep(time.Duration(retryDelay) * time.Millisecond)

		rand.Shuffle(len(retryQueue), func(i, j int) {
			retryQueue[i], retryQueue[j] = retryQueue[j], retryQueue[i]
		})

		for _, host := range retryQueue {
			if tracker.getState() == wafStateBlocked {
				if w.outputErrorLog {
					fmt.Printf("warning: 站点 %s 重试期间被硬封,停止重试\n", protocol+ip)
				}
				break
			}

			if waitDur := tracker.shouldWait(); waitDur > 0 {
				time.Sleep(waitDur)
			}

			extraDelay := 2000 + rand.Intn(3000)
			time.Sleep(time.Duration(extraDelay) * time.Millisecond)

			retryResult := w.collision(wafKey, baseRequest, errorHostRequest, protocol, ip, host, tracker, baseBodyHash, errorBodyHash)

			// 重试队列中也需要检测万能响应
			if catchAllEnabled && retryResult == collisionResultSuccess {
				ipSuccessCount++
				if ipSuccessCount >= catchAllThreshold {
					removed := w.removeCatchAllResults(protocol, ip)
					fmt.Printf("[万能响应IP检测] 协议:%s, IP:%s 重试阶段碰撞成功 %d 个Host(阈值%d), 判定为万能响应IP, 已清除 %d 条结果\n",
						protocol, ip, ipSuccessCount, catchAllThreshold, removed)
					break
				}
			}
		}
	}
}

// ========== 方案一: HEAD 预筛选 ==========

// headPreFilter 使用 HEAD 请求对 Host 列表进行预筛选
// 返回: (候选Host列表, 是否成功启用HEAD筛选)
// 安全保障:
//   - 服务不支持 HEAD（405/501）→ 返回 (nil, false)，回退到全量 GET
//   - HEAD 基准请求被 WAF 拦截 → 返回 (nil, false)，回退到全量 GET
//   - HEAD 响应与 GET 行为不一致的风险通过候选数量阈值兜底
func (w *Worker) headPreFilter(protocol, ip string, hosts []string, tracker *wafTracker) ([]string, bool) {
	// 1. 发送基准 HEAD 请求（无 Host 头）
	baseHead, err := httpclient.SendHTTPHeadRequest(protocol, ip, "")
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s HEAD基准请求失败, 回退到GET碰撞\n", protocol+ip)
		}
		return nil, false
	}

	// 检查服务是否支持 HEAD 方法
	// 405 Method Not Allowed / 501 Not Implemented 表示不支持 HEAD
	if baseHead.StatusCode == 405 || baseHead.StatusCode == 501 {
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s 不支持HEAD方法(状态码%d), 回退到GET碰撞\n",
				protocol+ip, baseHead.StatusCode)
		}
		return nil, false
	}

	// 检查 HEAD 基准是否被 WAF 拦截（通过 Server/X-Powered-By 头判断）
	if baseHead.XPoweredBy != "" {
		xpLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(baseHead.XPoweredBy, " ", "")))
		for _, bl := range w.xPoweredByBlacklists {
			if strings.Contains(xpLower, bl) {
				if w.outputErrorLog {
					fmt.Printf("info: 站点 %s HEAD基准请求命中WAF特征, 回退到GET碰撞\n", protocol+ip)
				}
				return nil, false
			}
		}
	}

	// 2. 发送绝对错误 Host 的 HEAD 请求
	errorHead, err := httpclient.SendHTTPHeadRequest(protocol, ip, w.cfg.HTTP.ErrorHost)
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s HEAD错误请求失败, 回退到GET碰撞\n", protocol+ip)
		}
		return nil, false
	}

	// 基准指纹
	baseFingerprint := baseHead.String()
	errorFingerprint := errorHead.String()

	// 3. 对每个 Host 发送 HEAD 请求，筛选出指纹不同的候选
	var candidates []string
	for _, host := range hosts {
		if waitDur := tracker.shouldWait(); waitDur > 0 {
			time.Sleep(waitDur)
		}

		hostHead, err := httpclient.SendHTTPHeadRequest(protocol, ip, host)
		if err != nil {
			// HEAD 请求失败的 Host 保留为候选（安全起见）
			candidates = append(candidates, host)
			continue
		}

		// 如果服务对某个 Host 返回 405/501，说明该 Host 可能有特殊路由
		// 保留为候选
		if hostHead.StatusCode == 405 || hostHead.StatusCode == 501 {
			candidates = append(candidates, host)
			continue
		}

		// 检查是否被 WAF 拦截（429 状态码）
		if hostHead.StatusCode == 429 {
			tracker.recordBlock()
			// WAF 拦截的 Host 保留为候选
			candidates = append(candidates, host)
			continue
		}

		hostFingerprint := hostHead.String()

		// 指纹与基准和错误请求都不同 → 候选
		if hostFingerprint != baseFingerprint && hostFingerprint != errorFingerprint {
			candidates = append(candidates, host)
		}
		// 指纹与基准或错误请求相同 → 过滤掉（大概率无效）
	}

	return candidates, true
}

// ========== 方案五: 自适应分阶段采样排除 ==========

// adaptiveSamplingElimination 自适应分阶段采样排除
// 分三个阶段逐步增加采样数量，对明显无效的 IP 更快跳过
// 返回 true 表示应跳过该 IP
func (w *Worker) adaptiveSamplingElimination(
	protocol, ip string, hosts []string, maxSampleSize int, tracker *wafTracker,
) bool {
	// 分阶段采样数量
	stages := []int{50, 200, maxSampleSize}

	var firstFingerprint string
	var totalSampled int

	for stageIdx, stageSize := range stages {
		if stageSize > len(hosts) {
			stageSize = len(hosts)
		}

		// 从上次采样的位置继续
		for i := totalSampled; i < stageSize; i++ {
			host := hosts[i]
			atomic.AddInt64(w.numOfRequest, 1)

			if waitDur := tracker.shouldWait(); waitDur > 0 {
				time.Sleep(waitDur)
			}

			sampleReq, err := httpclient.SendHTTPGetRequest(protocol, ip, host)
			if err != nil {
				continue
			}

			// WAF 拦截的响应不计入指纹比对（避免 WAF 干扰判断）
			if w.isWAFBlocked(sampleReq) {
				tracker.recordBlock()
				continue
			}
			tracker.recordSuccess()

			// 计算响应指纹: 状态码 + 内容长度 + Server头 + Title
			fingerprint := fmt.Sprintf("%d|%d|%s|%s",
				sampleReq.StatusCode, sampleReq.ContentLen,
				sampleReq.ServerHeader, sampleReq.Title())

			if firstFingerprint == "" {
				firstFingerprint = fingerprint
			} else if fingerprint != firstFingerprint {
				// 发现不同响应，说明该 IP 有 Host 路由，需要完整碰撞
				if w.outputErrorLog {
					fmt.Printf("info: 站点 %s 自适应采样阶段%d: 第%d个Host发现不同响应, 进入完整碰撞\n",
						protocol+ip, stageIdx+1, i+1)
				}
				return false
			}
		}

		totalSampled = stageSize

		// 如果当前阶段已经采样完所有 Host，直接判定
		if stageSize >= len(hosts) {
			break
		}
	}

	// 所有阶段采样的 Host 响应指纹都相同
	if firstFingerprint != "" {
		remainingCount := len(hosts) - totalSampled
		if remainingCount > 0 {
			atomic.AddInt64(w.numOfRequest, int64(remainingCount))
		}
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s 自适应采样 %d 个Host响应指纹全部相同, 跳过剩余 %d 个Host\n",
				protocol+ip, totalSampled, remainingCount)
		}
		return true
	}

	return false
}

// fixedSamplingElimination 固定采样排除（原有逻辑，作为回退方案）
// 返回 true 表示应跳过该 IP
func (w *Worker) fixedSamplingElimination(
	protocol, ip string, hosts []string, sampleSize int, tracker *wafTracker,
) bool {
	allSame := true
	var firstFingerprint string

	for i := 0; i < sampleSize && i < len(hosts); i++ {
		host := hosts[i]
		atomic.AddInt64(w.numOfRequest, 1)

		if waitDur := tracker.shouldWait(); waitDur > 0 {
			time.Sleep(waitDur)
		}

		sampleReq, err := httpclient.SendHTTPGetRequest(protocol, ip, host)
		if err != nil {
			continue
		}

		// WAF 拦截的响应不计入指纹比对
		if w.isWAFBlocked(sampleReq) {
			tracker.recordBlock()
			continue
		}
		tracker.recordSuccess()

		fingerprint := fmt.Sprintf("%d|%d|%s|%s",
			sampleReq.StatusCode, sampleReq.ContentLen,
			sampleReq.ServerHeader, sampleReq.Title())

		if firstFingerprint == "" {
			firstFingerprint = fingerprint
		} else if fingerprint != firstFingerprint {
			allSame = false
			break
		}
	}

	if allSame && firstFingerprint != "" {
		remainingCount := len(hosts) - sampleSize
		if remainingCount > 0 {
			atomic.AddInt64(w.numOfRequest, int64(remainingCount))
		}
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s 采样 %d 个Host响应指纹全部相同, 跳过剩余 %d 个Host\n",
				protocol+ip, sampleSize, remainingCount)
		}
		return true
	}

	return false
}

// collisionOutcome 碰撞结果类型
type collisionOutcome int

const (
	collisionResultSuccess    collisionOutcome = iota // 碰撞成功
	collisionResultFailed                             // 碰撞失败（正常过滤）
	collisionResultWAFBlocked                         // 被WAF拦截
	collisionResultError                              // 请求错误
)

// isWAFBlocked 检查请求是否被WAF拦截
func (w *Worker) isWAFBlocked(req *httpclient.HttpCustomRequest) bool {
	if req.StatusCode == 429 {
		return true
	}

	if s := req.ServerHeader; s != "" {
		sLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
		for _, bl := range w.serviceBlacklists {
			if strings.Contains(sLower, bl) {
				return true
			}
		}
	}

	if xp := req.XPoweredByVal; xp != "" {
		xpLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(xp, " ", "")))
		for _, bl := range w.xPoweredByBlacklists {
			if strings.Contains(xpLower, bl) {
				return true
			}
		}
	}

	if ab := req.AppBody(); ab != "" {
		abLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(ab, " ", "")))
		for _, bl := range w.bodyBlacklists {
			if strings.Contains(abLower, bl) {
				return true
			}
		}
	}

	return false
}

// collision Host碰撞核心逻辑
// 优化策略：
// 1. 先做轻量级检查（状态码、长度），再做重量级检查（相似度）
// 2. 延迟发送相对错误请求，只在通过初步检查后才发送
// 3. 使用带阈值的相似度计算，提前终止不可能达标的计算
// 4. WAF自适应退避：检测到WAF不放弃，而是退避后重试
// 5. 使用共享数据样本缓存，避免重复生成
// 6. 方案三: 基准指纹缓存 + FNV hash 快速比对，跳过编辑距离计算
func (w *Worker) collision(
	sampleKey string,
	baseRequest, errorHostRequest *httpclient.HttpCustomRequest,
	protocol, ip, host string,
	tracker *wafTracker,
	baseBodyHash, errorBodyHash uint64,
) collisionOutcome {
	// 碰撞请求
	newRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, host)
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-1(请求错误)\n", protocol, ip, host)
		}
		return collisionResultError
	}

	// ===== WAF 实时检测 =====
	if w.isWAFBlocked(newRequest) {
		backoffMs, shouldGiveUp := tracker.recordBlock()
		if shouldGiveUp {
			if w.outputErrorLog {
				fmt.Printf("warning: 协议:%s, ip:%s, host:%s 连续被WAF拦截,标记为硬封\n", protocol, ip, host)
			}
			return collisionResultWAFBlocked
		}
		if backoffMs > 0 {
			if w.outputErrorLog {
				fmt.Printf("info: 协议:%s, ip:%s, host:%s 被WAF拦截,退避 %dms,加入重试队列\n",
					protocol, ip, host, backoffMs)
			}
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
		}
		return collisionResultWAFBlocked
	}

	tracker.recordSuccess()

	// ===== 轻量级检查（不需要额外HTTP请求）=====

	// HTTP 状态码检查
	if !httpStatusCodeCheck(fmt.Sprintf("%d", newRequest.StatusCode), w.statusCodeWhitelist) {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 不是白名单状态码,忽略处理\n",
				protocol, ip, host, newRequest.Title(), newRequest.ContentLen, newRequest.StatusCode)
		}
		return collisionResultFailed
	}

	// 请求长度初步检查
	if newRequest.Location == "" && newRequest.ContentLen <= 0 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 该请求长度为%d 有异常,不进行碰撞-2\n",
				protocol, ip, host, newRequest.ContentLen)
		}
		return collisionResultFailed
	}

	// 快速内容比对
	newBody := newRequest.AppBody()
	baseBody := baseRequest.AppBody()
	errorBody := errorHostRequest.AppBody()

	if len(newBody) > 0 {
		if strings.Contains(newBody, baseBody) || strings.Contains(baseBody, newBody) {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-2(内容与基准相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	if len(errorBody) > 0 {
		if strings.Contains(newBody, errorBody) || strings.Contains(errorBody, newBody) {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-2(内容与错误请求相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	// 快速 title 比对
	newTitle := strings.TrimSpace(newRequest.Title())
	if len(newTitle) > 0 {
		if baseRequest.Title() == newTitle || errorHostRequest.Title() == newTitle {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-3(title与基准/错误相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	// ===== 方案三: 基准指纹缓存 + 快速比对 =====
	// 先用 FNV hash 做快速比对（O(n)），hash 相同则直接判定为相似
	// 只有 hash 不同时才做编辑距离计算（O(n*m)），大幅减少重量级计算
	newBodyFormat := newRequest.BodyFormat()
	if w.cfg.Optimization.EnableFingerprintCache && baseBodyHash > 0 {
		newBodyHash := fnvHash(newBodyFormat)
		// hash 完全相同 → 内容完全相同 → 直接判定为失败
		if newBodyHash == baseBodyHash {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(指纹与基准完全相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
		if newBodyHash == errorBodyHash {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(指纹与错误请求完全相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	// hash 不同，需要做编辑距离相似度检查
	_, exceeded1 := diffpage.GetRatioWithThreshold(baseRequest.BodyFormat(), newBodyFormat, w.cfg.SimilarityRatio)
	if exceeded1 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(与基准相似度过高)\n", protocol, ip, host)
		}
		return collisionResultFailed
	}

	_, exceeded2 := diffpage.GetRatioWithThreshold(errorHostRequest.BodyFormat(), newBodyFormat, w.cfg.SimilarityRatio)
	if exceeded2 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(与错误请求相似度过高)\n", protocol, ip, host)
		}
		return collisionResultFailed
	}

	// ===== 通过初步检查，发送相对错误请求进行深度验证 =====

	newRequest2, err := httpclient.SendHTTPGetRequest(protocol, ip, w.cfg.HTTP.RelativeHostName+host)
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-1(相对错误请求失败)\n", protocol, ip, host)
		}
		return collisionResultError
	}

	// 相对错误请求也检测WAF
	if w.isWAFBlocked(newRequest2) {
		tracker.recordBlock()
		if w.outputErrorLog {
			fmt.Printf("info: 协议:%s, ip:%s, host:%s 相对错误请求被WAF拦截,跳过相对比对\n", protocol, ip, host)
		}
	} else {
		// 相对错误请求的长度检查
		if newRequest2.Location == "" && newRequest2.ContentLen <= 0 {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 该请求长度为%d 有异常,不进行碰撞-2\n",
					protocol, ip, newRequest2.Host, newRequest2.ContentLen)
			}
			return collisionResultFailed
		}

		// 与相对错误请求的内容比对
		relativeBody := newRequest2.AppBody()
		if len(relativeBody) > 0 {
			if strings.Contains(newBody, relativeBody) || strings.Contains(relativeBody, newBody) {
				if w.outputErrorLog {
					fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-2(内容与相对错误请求相同)\n", protocol, ip, host)
				}
				return collisionResultFailed
			}
		}

		// 与相对错误请求的 title 比对
		if len(newTitle) > 0 && newRequest2.Title() == newTitle {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-3(title与相对错误请求相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}

		// 与相对错误请求的相似度检查
		_, exceeded3 := diffpage.GetRatioWithThreshold(newRequest2.BodyFormat(), newRequest.BodyFormat(), w.cfg.SimilarityRatio)
		if exceeded3 {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(与相对错误请求相似度过高)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	// 数据样本比对（使用共享缓存）
	if w.cfg.DataSample.Number > 0 {
		cache := getSampleCache()
		samples := cache.getOrCreateSamples(sampleKey, protocol, ip, w.cfg.HTTP.ErrorHost, w.cfg.DataSample.Number)
		if len(samples) > 0 {
			if sampleSimilarityCheck(newRequest.BodyFormat(), samples, w.cfg.SimilarityRatio) {
				if w.outputErrorLog {
					fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 数据样本匹配成功,可能为误报,忽略处理\n",
						protocol, ip, host, newRequest.Title(), newRequest.ContentLen, newRequest.StatusCode)
				}
				return collisionResultFailed
			}
		}
	}

	// WAF 检查（使用缓存的黑名单）
	if w.cfg.DataSample.Number > 0 {
		cache := getSampleCache()
		samples := cache.getOrCreateSamples(sampleKey, protocol, ip, w.cfg.HTTP.ErrorHost, w.cfg.DataSample.Number)
		if len(samples) > 0 {
			if ok, wafReq := w.wafFeatureMatchingCached(baseRequest, newRequest); !ok {
				if w.outputErrorLog {
					fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 匹配到waf特征,忽略处理\n",
						protocol, ip, wafReq.Host, wafReq.Title(), wafReq.ContentLen, wafReq.StatusCode)
				}
				return collisionResultFailed
			}
		}
	}

	// 碰撞成功！
	// 计算响应体 SimHash 指纹，用于后续相似内容聚合
	bodySimhash := simhash(newRequest.FilteredPageContent())

	result := &CollisionResult{
		Protocol:               protocol,
		IP:                     ip,
		Host:                   host,
		Title:                  newRequest.Title(),
		MatchContentLen:        newRequest.ContentLen,
		BaseContentLen:         baseRequest.ContentLen,
		ErrorHostContentLen:    errorHostRequest.ContentLen,
		RelativeHostContentLen: newRequest2.ContentLen,
		MatchStatusCode:        newRequest.StatusCode,
		BaseStatusCode:         baseRequest.StatusCode,
		ErrorHostStatusCode:    errorHostRequest.StatusCode,
		RelativeHostStatusCode: newRequest2.StatusCode,
		BodySimhash:            bodySimhash,
	}

	// 去重检查：Protocol+IP+Host 构成唯一键，避免重复结果
	dedupKey := protocol + "|" + ip + "|" + host
	w.resultsMu.Lock()
	if _, exists := w.resultDedup[dedupKey]; exists {
		w.resultsMu.Unlock()
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 碰撞成功但已存在相同结果,跳过\n", protocol, ip, host)
		}
		return collisionResultFailed
	}
	w.resultDedup[dedupKey] = struct{}{}
	*w.results = append(*w.results, result)
	w.resultsMu.Unlock()

	// 实时输出成功日志
	fmt.Println(result.SuccessLog())

	return collisionResultSuccess
}

// ========== 工具函数 ==========

// requestLengthMatching 请求之间的长度判断
// 用途: 初步的误报检测
// 返回: true 表示通过, false 表示未通过（并返回异常的请求）
func requestLengthMatching(requests []*httpclient.HttpCustomRequest) (bool, *httpclient.HttpCustomRequest) {
	for _, r := range requests {
		if r.Location == "" && r.ContentLen <= 0 {
			return false, r
		}
	}
	return true, nil
}

// sampleSimilarityCheck 样本相似度检查
// 用于判断当前字符串与样本数组是否有相似的数据出现
// true 表示有相似数据出现, false 表示没有相似数据出现
func sampleSimilarityCheck(str string, samples []*httpclient.HttpCustomRequest, ratio float64) bool {
	for _, r := range samples {
		_, exceeded := diffpage.GetRatioWithThreshold(r.BodyFormat(), str, ratio)
		if exceeded {
			return true
		}
	}
	return false
}

// httpStatusCodeCheck HTTP 状态码检查
// 如果不为白名单里面的状态码,则表示验证失败
// true 表示通过, false 表示不通过
func httpStatusCodeCheck(code string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	for _, c := range whitelist {
		if c == code {
			return true
		}
	}
	return false
}

// parseStatusCodes 解析碰撞成功状态码配置（只解析一次，结果被缓存）
func parseStatusCodes(statusCodeStr string) []string {
	var result []string
	parts := strings.Split(strings.TrimSpace(strings.ToLower(statusCodeStr)), ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ========== 方案六: 万能响应IP检测 ==========

// removeCatchAllResults 标记指定 IP+协议 的所有碰撞结果为无效
// 当检测到某个 IP 为"万能响应"IP 时，将其所有已记录的碰撞结果标记为 Invalid
// 使用标记式删除而非物理删除，避免与 RunWithCallback 的回调索引产生并发冲突
// 返回被标记的结果数量
func (w *Worker) removeCatchAllResults(protocol, ip string) int {
	w.resultsMu.Lock()
	defer w.resultsMu.Unlock()

	marked := 0
	for _, r := range *w.results {
		if r.Protocol == protocol && r.IP == ip && !r.Invalid {
			r.Invalid = true
			marked++
		}
	}
	return marked
}

// wafFeatureMatchingCached 使用缓存黑名单的 WAF 特征匹配
// 返回: true 表示通过(无 WAF), false 表示匹配到 WAF
func (w *Worker) wafFeatureMatchingCached(baseReq, newReq *httpclient.HttpCustomRequest) (bool, *httpclient.HttpCustomRequest) {
	if w.httpHeaderServiceWafMatchingCached(baseReq, newReq) {
		return false, newReq
	}
	if w.httpBodyWafMatchingCached(baseReq, newReq) {
		return false, newReq
	}
	if w.httpHeaderXPoweredByWafMatchingCached(baseReq, newReq) {
		return false, newReq
	}
	return true, nil
}

// httpHeaderServiceWafMatchingCached HTTP 请求 header Server 字段的 WAF 特征匹配（使用缓存黑名单）
func (w *Worker) httpHeaderServiceWafMatchingCached(baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bs := baseReq.ServerHeader
	s := newReq.ServerHeader

	if bs != "" && s != "" {
		if bs == s {
			return false
		}
	}

	if s != "" && len(w.serviceBlacklists) > 0 {
		sLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
		for _, bl := range w.serviceBlacklists {
			bl = strings.ReplaceAll(bl, " ", "")
			if strings.Contains(sLower, bl) {
				return true
			}
		}
	}
	return false
}

// httpBodyWafMatchingCached HTTP 请求 body 的 WAF 特征匹配（使用缓存黑名单）
func (w *Worker) httpBodyWafMatchingCached(baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bab := baseReq.AppBody()
	ab := newReq.AppBody()

	if bab != "" && ab != "" {
		if bab == ab {
			return false
		}
	}

	if ab != "" && len(w.bodyBlacklists) > 0 {
		abLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(ab, " ", "")))
		for _, bl := range w.bodyBlacklists {
			bl = strings.ReplaceAll(bl, " ", "")
			if strings.Contains(abLower, bl) {
				return true
			}
		}
	}
	return false
}

// httpHeaderXPoweredByWafMatchingCached HTTP 请求 header X-Powered-By 字段的 WAF 特征匹配（使用缓存黑名单）
func (w *Worker) httpHeaderXPoweredByWafMatchingCached(baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bxp := baseReq.XPoweredByVal
	xp := newReq.XPoweredByVal

	if bxp != "" && xp != "" {
		if bxp == xp {
			return false
		}
	}

	if xp != "" && len(w.xPoweredByBlacklists) > 0 {
		xpLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(xp, " ", "")))
		for _, bl := range w.xPoweredByBlacklists {
			bl = strings.ReplaceAll(bl, " ", "")
			if strings.Contains(xpLower, bl) {
				return true
			}
		}
	}
	return false
}

// ========== SimHash 局部敏感哈希 ==========

// simhash 计算文本的 64 位 SimHash 指纹（局部敏感哈希）
// SimHash 的核心特性：相似的文本产生相似的 hash 值，可通过海明距离判断相似度
// 海明距离 ≤ 3 即认为内容高度相似，适合对碰撞结果进行聚合去重
//
// 算法流程:
//  1. 将文本按空格/标点分词为 token 列表
//  2. 对每个 token 计算 FNV-1a 64位 hash
//  3. 构建 64 维加权向量：hash 的每一位为 1 则 +1，为 0 则 -1
//  4. 向量每一维正数映射为 1，非正数映射为 0，组成 64 位指纹
func simhash(text string) uint64 {
	if text == "" {
		return 0
	}

	// 分词：按非字母数字字符和中文字符边界切分
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return 0
	}

	// 64 维加权向量
	var vector [64]int

	for _, token := range tokens {
		// 计算每个 token 的 FNV-1a hash
		h := fnvHash(token)
		if h == 0 {
			continue
		}

		// 根据 hash 的每一位更新向量
		for i := 0; i < 64; i++ {
			if (h>>uint(i))&1 == 1 {
				vector[i]++
			} else {
				vector[i]--
			}
		}
	}

	// 向量降维为 64 位指纹
	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if vector[i] > 0 {
			fingerprint |= 1 << uint(i)
		}
	}

	return fingerprint
}

// tokenize 将文本分词为 token 列表
// 支持英文（按空格/标点分割）和中文（按字符切分，使用 bigram）
func tokenize(text string) []string {
	if len(text) == 0 {
		return nil
	}

	runes := []rune(text)
	var tokens []string
	var current []rune

	for _, r := range runes {
		if isTokenChar(r) {
			current = append(current, r)
		} else {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = current[:0]
			}
		}
	}
	if len(current) > 0 {
		tokens = append(tokens, string(current))
	}

	// 对中文内容使用 bigram（二元组）增强指纹区分度
	// 如果 token 包含中文字符且长度 >= 2，生成 bigram
	var result []string
	for _, token := range tokens {
		tr := []rune(token)
		if len(tr) >= 2 && hasCJK(tr) {
			// 生成 bigram
			for i := 0; i < len(tr)-1; i++ {
				result = append(result, string(tr[i:i+2]))
			}
		} else {
			result = append(result, token)
		}
	}

	return result
}

// isTokenChar 判断字符是否为有效 token 字符（字母、数字、中文等）
func isTokenChar(r rune) bool {
	// ASCII 字母和数字
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
		return true
	}
	// CJK 统一汉字（常用中文范围）
	if r >= 0x4E00 && r <= 0x9FFF {
		return true
	}
	// CJK 扩展 A
	if r >= 0x3400 && r <= 0x4DBF {
		return true
	}
	// 日文平假名和片假名
	if r >= 0x3040 && r <= 0x30FF {
		return true
	}
	// 韩文音节
	if r >= 0xAC00 && r <= 0xD7AF {
		return true
	}
	return false
}

// hasCJK 检查 rune 切片中是否包含 CJK 字符
func hasCJK(runes []rune) bool {
	for _, r := range runes {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
		if r >= 0x3400 && r <= 0x4DBF {
			return true
		}
		if r >= 0x3040 && r <= 0x30FF {
			return true
		}
		if r >= 0xAC00 && r <= 0xD7AF {
			return true
		}
	}
	return false
}

// SimhashDistance 计算两个 SimHash 指纹的海明距离
// 海明距离 ≤ 3 表示内容高度相似
func SimhashDistance(a, b uint64) int {
	xor := a ^ b
	dist := 0
	for xor != 0 {
		dist++
		xor &= xor - 1 // Brian Kernighan 算法，每次消除最低位的 1
	}
	return dist
}

// ========== 方案三: FNV hash 指纹计算 ==========

// fnvHash 使用 FNV-1a 算法计算字符串的 64 位 hash 指纹
// FNV-1a 是一种非加密 hash 算法，速度极快（比 MD5/SHA 快 10 倍以上）
// 用于快速判断两个字符串是否相同，避免昂贵的编辑距离计算
// 注意: hash 相同 → 内容极大概率相同（FNV-1a 碰撞率极低）
//
//	hash 不同 → 内容一定不同
func fnvHash(s string) uint64 {
	if s == "" {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
