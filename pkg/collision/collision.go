package collision

import (
	"fmt"
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
}

// CSVHeaders CSV 表头
func CSVHeaders() []string {
	return []string{
		"协议", "ip", "host", "标题",
		"匹配成功的数据包大小", "原始的数据包大小", "绝对错误的数据包大小", "相对错误的数据包大小",
		"匹配成功的数据包状态码", "原始的数据包状态码", "绝对错误的数据包状态码", "相对错误的数据包状态码",
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
	}
}

// ToTXTRecord 转换为 TXT 记录
func (r *CollisionResult) ToTXTRecord() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 匹配成功的数据包大小:%d, 状态码:%d 匹配成功",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode)
}

// SuccessLog 匹配成功日志
func (r *CollisionResult) SuccessLog() string {
	return fmt.Sprintf("协议:%s, ip:%s, host:%s, title:%s, 匹配成功的数据包大小:%d, 状态码:%d 匹配成功",
		r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode)
}

// ========== 碰撞工作器 ==========

// Worker Host碰撞工作器
type Worker struct {
	cfg            *config.Config
	numOfRequest   *int64 // 原子计数器：请求数
	results        *[]*CollisionResult
	resultsMu      *sync.Mutex
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
func NewWorker(
	cfg *config.Config,
	numOfRequest *int64,
	results *[]*CollisionResult,
	resultsMu *sync.Mutex,
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

// Run 执行碰撞任务
func (w *Worker) Run() {
	w.initCache()
	for _, ip := range w.ipList {
		for _, protocol := range w.scanProtocols {
			w.processIPProtocol(protocol, ip)
		}
	}
}

// processIPProtocol 处理单个 IP + 协议的碰撞
func (w *Worker) processIPProtocol(protocol, ip string) {
	// 数据样本（同一个 ip + 协议 只生成一次）
	var dataSample []*httpclient.HttpCustomRequest

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
	// 注意：这里不再直接放弃，而是记录WAF状态并调整策略
	if w.isWAFBlocked(baseRequest) {
		// 基准请求就被WAF拦截，说明该IP可能有全局WAF
		// 记录拦截，获取退避建议
		backoffMs, shouldGiveUp := tracker.recordBlock()
		if shouldGiveUp {
			// 连续大量拦截，确认为硬封，放弃
			atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
			if w.outputErrorLog {
				fmt.Printf("warning: 站点 %s 连续被WAF拦截超过阈值,放弃碰撞\n", protocol+ip)
			}
			return
		}
		// 退避等待后重试基准请求
		if backoffMs > 0 {
			if w.outputErrorLog {
				fmt.Printf("info: 站点 %s 基准请求命中WAF特征,退避 %dms 后重试\n", protocol+ip, backoffMs)
			}
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			// 重试基准请求
			baseRequest, err = httpclient.SendHTTPGetRequest(protocol, ip, "")
			if err != nil {
				atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
				return
			}
			// 重试后仍然被拦截
			if w.isWAFBlocked(baseRequest) {
				// 再次记录拦截
				_, shouldGiveUp2 := tracker.recordBlock()
				if shouldGiveUp2 {
					atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
					if w.outputErrorLog {
						fmt.Printf("warning: 站点 %s 重试后仍被WAF拦截,放弃碰撞\n", protocol+ip)
					}
					return
				}
				// 即使基准被拦截，仍然尝试碰撞（因为不同Host可能有不同的WAF策略）
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

	// 打散 Host 列表顺序，避免按固定模式发送请求
	// 这样可以降低被WAF基于请求模式识别的风险
	shuffledHosts := make([]string, len(w.hostList))
	copy(shuffledHosts, w.hostList)
	rand.Shuffle(len(shuffledHosts), func(i, j int) {
		shuffledHosts[i], shuffledHosts[j] = shuffledHosts[j], shuffledHosts[i]
	})

	// 重试队列：被WAF拦截的Host放入重试队列
	var retryQueue []string

	for _, host := range shuffledHosts {
		atomic.AddInt64(w.numOfRequest, 1)

		// 检查是否需要等待退避
		if waitDur := tracker.shouldWait(); waitDur > 0 {
			time.Sleep(waitDur)
		}

		result := w.collision(&dataSample, baseRequest, errorHostRequest, protocol, ip, host, tracker)
		if result == collisionResultWAFBlocked {
			// 被WAF拦截，加入重试队列
			retryQueue = append(retryQueue, host)
		}
	}

	// 处理重试队列：等待一段时间后重试被WAF拦截的Host
	if len(retryQueue) > 0 && tracker.getState() != wafStateBlocked {
		// 等待一个较长的退避时间
		retryDelay := 5000 + rand.Intn(10000) // 5-15秒
		if w.outputErrorLog {
			fmt.Printf("info: 站点 %s 有 %d 个Host被WAF拦截,等待 %dms 后重试\n",
				protocol+ip, len(retryQueue), retryDelay)
		}
		time.Sleep(time.Duration(retryDelay) * time.Millisecond)

		// 重新打散重试队列
		rand.Shuffle(len(retryQueue), func(i, j int) {
			retryQueue[i], retryQueue[j] = retryQueue[j], retryQueue[i]
		})

		for _, host := range retryQueue {
			// 检查是否已经被硬封
			if tracker.getState() == wafStateBlocked {
				if w.outputErrorLog {
					fmt.Printf("warning: 站点 %s 重试期间被硬封,停止重试\n", protocol+ip)
				}
				break
			}

			// 检查退避
			if waitDur := tracker.shouldWait(); waitDur > 0 {
				time.Sleep(waitDur)
			}

			// 重试时增加额外的随机延迟（2-5秒），降低被检测风险
			extraDelay := 2000 + rand.Intn(3000)
			time.Sleep(time.Duration(extraDelay) * time.Millisecond)

			w.collision(&dataSample, baseRequest, errorHostRequest, protocol, ip, host, tracker)
		}
	}
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
// 通过检查响应体和响应头中的WAF特征来判断
func (w *Worker) isWAFBlocked(req *httpclient.HttpCustomRequest) bool {
	// 检查常见的WAF拦截状态码
	// 403 可能是正常的权限拒绝，但结合其他特征可以判断
	// 429 是明确的频率限制
	// 503 可能是WAF的挑战页面
	if req.StatusCode == 429 {
		return true
	}

	// 检查 Server 头
	if s := req.ServerHeader; s != "" {
		sLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
		for _, bl := range w.serviceBlacklists {
			if strings.Contains(sLower, bl) {
				return true
			}
		}
	}

	// 检查 X-Powered-By 头
	if xp := req.XPoweredByVal; xp != "" {
		xpLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(xp, " ", "")))
		for _, bl := range w.xPoweredByBlacklists {
			if strings.Contains(xpLower, bl) {
				return true
			}
		}
	}

	// 检查响应体中的WAF特征
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
func (w *Worker) collision(
	dataSample *[]*httpclient.HttpCustomRequest,
	baseRequest, errorHostRequest *httpclient.HttpCustomRequest,
	protocol, ip, host string,
	tracker *wafTracker,
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
	// 每个碰撞请求都检测WAF，而不仅仅是基准请求
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
			// 退避等待
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
		}
		return collisionResultWAFBlocked
	}

	// 请求未被WAF拦截，记录成功
	tracker.recordSuccess()

	// ===== 轻量级检查（不需要额外HTTP请求）=====

	// HTTP 状态码检查（提前到最前面，避免无效的后续计算）
	if !httpStatusCodeCheck(fmt.Sprintf("%d", newRequest.StatusCode), w.statusCodeWhitelist) {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 不是白名单状态码,忽略处理\n",
				protocol, ip, host, newRequest.Title(), newRequest.ContentLen, newRequest.StatusCode)
		}
		return collisionResultFailed
	}

	// 请求长度初步检查（只检查碰撞请求本身）
	if newRequest.Location == "" && newRequest.ContentLen <= 0 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 该请求长度为%d 有异常,不进行碰撞-2\n",
				protocol, ip, host, newRequest.ContentLen)
		}
		return collisionResultFailed
	}

	// 快速内容比对（与基准请求和错误请求比较，不需要额外HTTP请求）
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

	// 快速 title 比对（与基准请求和错误请求比较）
	newTitle := strings.TrimSpace(newRequest.Title())
	if len(newTitle) > 0 {
		if baseRequest.Title() == newTitle || errorHostRequest.Title() == newTitle {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-3(title与基准/错误相同)\n", protocol, ip, host)
			}
			return collisionResultFailed
		}
	}

	// 快速相似度检查（与基准请求和错误请求比较，使用带阈值的提前终止）
	_, exceeded1 := diffpage.GetRatioWithThreshold(baseRequest.BodyFormat(), newRequest.BodyFormat(), w.cfg.SimilarityRatio)
	if exceeded1 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(与基准相似度过高)\n", protocol, ip, host)
		}
		return collisionResultFailed
	}

	_, exceeded2 := diffpage.GetRatioWithThreshold(errorHostRequest.BodyFormat(), newRequest.BodyFormat(), w.cfg.SimilarityRatio)
	if exceeded2 {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4(与错误请求相似度过高)\n", protocol, ip, host)
		}
		return collisionResultFailed
	}

	// ===== 通过初步检查，发送相对错误请求进行深度验证 =====
	// 延迟发送：只有通过了上面所有轻量级检查才发送这个请求
	// 这样可以大幅减少实际发出的HTTP请求数量

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
		// 相对错误请求被WAF拦截，但碰撞请求本身没有被拦截
		// 这种情况下碰撞请求的结果仍然有参考价值，继续处理
		if w.outputErrorLog {
			fmt.Printf("info: 协议:%s, ip:%s, host:%s 相对错误请求被WAF拦截,跳过相对比对\n", protocol, ip, host)
		}
		// 跳过与相对错误请求的比对，直接进入数据样本和WAF特征检查
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

	// 数据样本生成（延迟生成，只在第一次需要时才创建）
	if w.cfg.DataSample.Number > 0 && len(*dataSample) == 0 {
		for i := 0; i < w.cfg.DataSample.Number; i++ {
			sampleReq, err := httpclient.SendHTTPGetRequest(protocol, ip, w.cfg.HTTP.ErrorHost)
			if err == nil {
				*dataSample = append(*dataSample, sampleReq)
			}
		}
	}

	// 数据样本比对
	if len(*dataSample) > 0 {
		if sampleSimilarityCheck(newRequest.BodyFormat(), *dataSample, w.cfg.SimilarityRatio) {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 数据样本匹配成功,可能为误报,忽略处理\n",
					protocol, ip, host, newRequest.Title(), newRequest.ContentLen, newRequest.StatusCode)
			}
			return collisionResultFailed
		}
	}

	// WAF 检查（使用缓存的黑名单）
	if w.cfg.DataSample.Number > 0 && len(*dataSample) > 0 {
		if ok, wafReq := w.wafFeatureMatchingCached(baseRequest, newRequest); !ok {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 匹配到waf特征,忽略处理\n",
					protocol, ip, wafReq.Host, wafReq.Title(), wafReq.ContentLen, wafReq.StatusCode)
			}
			return collisionResultFailed
		}
	}

	// 碰撞成功！
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
	}

	// 保存碰撞成功的数据
	w.resultsMu.Lock()
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
