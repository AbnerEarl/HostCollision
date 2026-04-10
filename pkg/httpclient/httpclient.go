package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/diffpage"
	"github.com/AbnerEarl/HostCollision/pkg/helpers"
)

// ========== 常量定义 ==========

// maxResponseBodySize 最大响应体读取大小（512KB），防止大页面导致内存爆炸
const maxResponseBodySize = 512 * 1024

// ========== User-Agent 随机池 ==========

// userAgentPool 常见浏览器 User-Agent 池，涵盖 Chrome/Firefox/Safari/Edge 多平台多版本
var userAgentPool = []string{
	// Chrome - Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	// Chrome - macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	// Chrome - Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Firefox - Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
	// Firefox - macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	// Firefox - Linux
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	// Safari - macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	// Edge - Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
	// Edge - macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
}

// defaultUA 默认 User-Agent（不开启随机化时使用）
const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// GetRandomUA 从 UA 池中随机选取一个 User-Agent
func GetRandomUA() string {
	return userAgentPool[rand.Intn(len(userAgentPool))]
}

// ========== 请求指纹多样化（绕过WAF指纹检测）==========

// acceptVariants Accept 头变体池
// 不同浏览器发送的 Accept 头略有不同，随机选择可以分散WAF指纹
var acceptVariants = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
}

// acceptLanguageVariants Accept-Language 头变体池
var acceptLanguageVariants = []string{
	"zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
	"en-US,en;q=0.9",
	"en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
	"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7",
	"ja,en-US;q=0.9,en;q=0.8",
}

// fakeIPPool 伪造源IP池（用于 X-Forwarded-For 等头部）
// 使用常见的内网IP和CDN节点IP，让WAF认为请求来自可信来源
var fakeIPPool = []string{
	"127.0.0.1",
	"10.0.0.1",
	"10.10.10.1",
	"172.16.0.1",
	"172.16.1.1",
	"192.168.0.1",
	"192.168.1.1",
	"192.168.1.100",
	"100.64.0.1",
	"169.254.169.254",
}

// getRandomFakeIP 获取随机伪造IP
func getRandomFakeIP() string {
	return fakeIPPool[rand.Intn(len(fakeIPPool))]
}

// getRandomAccept 获取随机 Accept 头
func getRandomAccept() string {
	return acceptVariants[rand.Intn(len(acceptVariants))]
}

// getRandomAcceptLanguage 获取随机 Accept-Language 头
func getRandomAcceptLanguage() string {
	return acceptLanguageVariants[rand.Intn(len(acceptLanguageVariants))]
}

// ========== HTTP 连接池管理器 ==========

// TransportPool 按 IP+协议 维度复用 Transport，避免重复 TLS 握手
// 同一个 IP+协议 的多次请求（不同Host头）可以复用底层TCP连接
type TransportPool struct {
	mu         sync.RWMutex
	transports map[string]*http.Transport
	cfg        *config.Config
}

var (
	transportPool     *TransportPool
	transportPoolOnce sync.Once
)

// GetTransportPool 获取连接池单例
func GetTransportPool() *TransportPool {
	transportPoolOnce.Do(func() {
		transportPool = &TransportPool{
			transports: make(map[string]*http.Transport),
		}
	})
	return transportPool
}

// ResetTransportPool 重置连接池（库模式下多次调用时使用）
func ResetTransportPool() {
	if transportPool != nil {
		transportPool.mu.Lock()
		for _, t := range transportPool.transports {
			t.CloseIdleConnections()
		}
		transportPool.mu.Unlock()
	}
	transportPoolOnce = sync.Once{}
	transportPool = nil
}

// GetTransport 获取或创建指定 IP+协议 的 Transport
// 同一个 IP 的不同 Host 请求共享同一个 Transport，实现连接复用
func (tp *TransportPool) GetTransport(key string, cfg *config.Config) *http.Transport {
	tp.mu.RLock()
	t, ok := tp.transports[key]
	tp.mu.RUnlock()
	if ok {
		return t
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()

	// 双重检查
	if t, ok = tp.transports[key]; ok {
		return t
	}

	t = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.HTTP.ConnectTimeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: time.Duration(cfg.HTTP.ReadTimeout) * time.Second,
		// 启用连接复用：同一个IP的不同Host请求可以复用TCP连接
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// 代理配置（代理池优先 > 单一代理）
	if cfg.HTTP.ProxyPool.IsStart {
		pm := GetProxyPoolManager()
		if pm.Size() > 0 {
			// 代理池模式：每次请求动态选择代理
			t.Proxy = func(req *http.Request) (*url.URL, error) {
				proxyAddr := pm.Next()
				return url.Parse(proxyAddr)
			}
		}
	} else if cfg.HTTP.Proxy.IsStart {
		proxyStr := fmt.Sprintf("http://%s:%d", cfg.HTTP.Proxy.Host, cfg.HTTP.Proxy.Port)
		if cfg.HTTP.Proxy.Username != "" {
			proxyStr = fmt.Sprintf("http://%s:%s@%s:%d",
				cfg.HTTP.Proxy.Username, cfg.HTTP.Proxy.Password,
				cfg.HTTP.Proxy.Host, cfg.HTTP.Proxy.Port)
		}
		proxyURL, err := url.Parse(proxyStr)
		if err == nil {
			t.Proxy = http.ProxyURL(proxyURL)
		}
	}

	tp.transports[key] = t
	return t
}

// ========== 代理池管理器 ==========

// ProxyPoolManager 代理池管理器，支持轮换代理
type ProxyPoolManager struct {
	proxies []string
	index   uint64
	mu      sync.RWMutex
}

var (
	proxyPool     *ProxyPoolManager
	proxyPoolOnce sync.Once
)

// GetProxyPoolManager 获取代理池单例
func GetProxyPoolManager() *ProxyPoolManager {
	proxyPoolOnce.Do(func() {
		proxyPool = &ProxyPoolManager{}
	})
	return proxyPool
}

// ResetProxyPoolManager 重置代理池管理器（库模式下多次调用时使用）
func ResetProxyPoolManager() {
	proxyPoolOnce = sync.Once{}
	proxyPool = nil
}

// Load 加载代理列表
func (p *ProxyPoolManager) Load(proxies []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	p.index = 0
}

// Next 获取下一个代理地址（轮询方式）
func (p *ProxyPoolManager) Next() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.proxies) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&p.index, 1)
	return p.proxies[(idx-1)%uint64(len(p.proxies))]
}

// Size 返回代理池大小
func (p *ProxyPoolManager) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// ========== 全局速率限制器 ==========

// RateLimiter 基于令牌桶的全局速率限制器
type RateLimiter struct {
	tokens   chan struct{}
	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	globalRateLimiter *RateLimiter
	rateLimiterOnce   sync.Once
)

// InitRateLimiter 初始化全局速率限制器
// ratePerSecond: 每秒最大请求数，0 表示不限制
func InitRateLimiter(ratePerSecond int) {
	rateLimiterOnce.Do(func() {
		if ratePerSecond <= 0 {
			globalRateLimiter = nil
			return
		}
		rl := &RateLimiter{
			tokens: make(chan struct{}, ratePerSecond),
			stopCh: make(chan struct{}),
		}
		// 预填充令牌桶，避免启动时的冷启动延迟
		for i := 0; i < ratePerSecond; i++ {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
		go func() {
			interval := time.Second / time.Duration(ratePerSecond)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					select {
					case rl.tokens <- struct{}{}:
					default:
					}
				case <-rl.stopCh:
					return
				}
			}
		}()
		globalRateLimiter = rl
	})
}

// ResetRateLimiter 重置速率限制器（库模式下多次调用时使用）
func ResetRateLimiter() {
	if globalRateLimiter != nil {
		globalRateLimiter.stopOnce.Do(func() {
			close(globalRateLimiter.stopCh)
		})
	}
	rateLimiterOnce = sync.Once{}
	globalRateLimiter = nil
}

// Wait 等待获取一个令牌（阻塞直到获取或 context 取消）
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ========== 请求延迟控制 ==========

// ApplyDelay 应用请求延迟（随机等待 minMs~maxMs 毫秒）
func ApplyDelay(cfg *config.Config) {
	if !cfg.AntiDetection.Delay.IsStart {
		return
	}
	minMs := cfg.AntiDetection.Delay.MinMs
	maxMs := cfg.AntiDetection.Delay.MaxMs
	if minMs <= 0 && maxMs <= 0 {
		return
	}
	if minMs > maxMs {
		minMs, maxMs = maxMs, minMs
	}
	if minMs <= 0 {
		minMs = 0
	}
	delay := minMs
	if maxMs > minMs {
		delay = minMs + rand.Intn(maxMs-minMs+1)
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// ========== HTTP 请求响应封装 ==========

// HttpCustomRequest 自定义HTTP请求响应封装
type HttpCustomRequest struct {
	Host          string // 请求使用的 Host
	Body          string // 响应体
	StatusCode    int    // HTTP 状态码
	ContentLen    int    // Content-Length
	Location      string // Location 头
	ServerHeader  string // Server 头
	XPoweredByVal string // X-Powered-By 头

	// 缓存字段，避免重复计算
	cachedAppBody      string
	cachedBodyFormat   string
	cachedTitle        string
	appBodyComputed    bool
	bodyFormatComputed bool
	titleComputed      bool
}

// Title 获取网页标题（带缓存）
func (r *HttpCustomRequest) Title() string {
	if !r.titleComputed {
		r.cachedTitle = helpers.GetBodyTitle(r.AppBody())
		r.titleComputed = true
	}
	return r.cachedTitle
}

// AppBody 获取经过处理的响应体（带缓存）
// 如果有 Location 跳转，提取其中的 URL 主机部分
func (r *HttpCustomRequest) AppBody() string {
	if !r.appBodyComputed {
		if r.Location != "" {
			u, err := url.Parse(r.Location)
			if err != nil {
				r.cachedAppBody = ""
			} else if u.Host != "" {
				r.cachedAppBody = u.Scheme + "://" + u.Host
			} else {
				r.cachedAppBody = ""
			}
		} else {
			r.cachedAppBody = r.Body
		}
		r.appBodyComputed = true
	}
	return r.cachedAppBody
}

// BodyFormat 获取格式化后的响应体（替换掉host）（带缓存）
func (r *HttpCustomRequest) BodyFormat() string {
	if !r.bodyFormatComputed {
		r.cachedBodyFormat = strings.ReplaceAll(r.AppBody(), r.Host, "")
		r.bodyFormatComputed = true
	}
	return r.cachedBodyFormat
}

// FilteredPageContent 获取过滤后的页面内容
func (r *HttpCustomRequest) FilteredPageContent() string {
	return diffpage.GetFilteredPageContent(r.BodyFormat())
}

// ========== 核心 HTTP 请求函数 ==========

// SendHTTPGetRequestQuick 快速发送HTTP GET请求（用于IP预检测）
// 不受速率限制和延迟扫描影响，使用较短的超时时间
func SendHTTPGetRequestQuick(protocol, ip, host string) (*HttpCustomRequest, error) {
	cfg := config.GetInstance()

	targetURL := protocol + ip

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true, // 预检测不需要连接复用
	}

	// 代理配置
	if cfg.HTTP.ProxyPool.IsStart {
		pm := GetProxyPoolManager()
		if pm.Size() > 0 {
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				proxyAddr := pm.Next()
				return url.Parse(proxyAddr)
			}
		}
	} else if cfg.HTTP.Proxy.IsStart {
		proxyStr := fmt.Sprintf("http://%s:%d", cfg.HTTP.Proxy.Host, cfg.HTTP.Proxy.Port)
		proxyURL, err := url.Parse(proxyStr)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")

	if host != "" {
		req.Host = host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 预检测只读取少量数据
	limitedReader := io.LimitReader(resp.Body, 4096)
	body, _ := io.ReadAll(limitedReader)
	io.Copy(io.Discard, resp.Body)

	requestHost := host
	if requestHost == "" {
		requestHost = ip
	}

	return &HttpCustomRequest{
		Host:          requestHost,
		Body:          string(body),
		StatusCode:    resp.StatusCode,
		ContentLen:    int(resp.ContentLength),
		Location:      resp.Header.Get("Location"),
		ServerHeader:  resp.Header.Get("Server"),
		XPoweredByVal: resp.Header.Get("X-Powered-By"),
	}, nil
}

// SendHTTPGetRequest 发送HTTP GET请求
// 支持: UA 随机化、Header 伪造、代理池轮换、速率限制、延迟扫描、连接池复用
func SendHTTPGetRequest(protocol, ip, host string) (*HttpCustomRequest, error) {
	cfg := config.GetInstance()

	// ===== 速率限制：等待令牌 =====
	if globalRateLimiter != nil {
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(cfg.HTTP.ReadTimeout+cfg.HTTP.ConnectTimeout+10)*time.Second)
		defer cancel()
		if err := globalRateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("速率限制等待超时: %w", err)
		}
	}

	// ===== 延迟扫描：随机等待 =====
	ApplyDelay(cfg)

	// ===== 选择 User-Agent =====
	userAgent := defaultUA
	if cfg.AntiDetection.RandomUA {
		userAgent = GetRandomUA()
	}

	targetURL := protocol + ip

	// ===== 获取连接池中的 Transport（按 IP+协议 复用）=====
	transportKey := protocol + ip
	tp := GetTransportPool()
	transport := tp.GetTransport(transportKey, cfg)

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.HTTP.ReadTimeout+cfg.HTTP.ConnectTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// ===== 设置请求头（多样化指纹，绕过WAF指纹检测）=====
	req.Header.Set("User-Agent", userAgent)
	if cfg.AntiDetection.RandomUA {
		// 随机化 Accept 和 Accept-Language，分散请求指纹
		req.Header.Set("Accept", getRandomAccept())
		req.Header.Set("Accept-Language", getRandomAcceptLanguage())
	} else {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7")
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")
	// 随机决定是否发送 Cache-Control（减少请求指纹一致性）
	if rand.Intn(2) == 0 {
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
	} else {
		req.Header.Set("Cache-Control", "max-age=0")
	}

	// ===== Header 伪造（Bypass WAF）=====
	if cfg.AntiDetection.FakeHeaders.IsStart {
		// 使用随机伪造IP替代固定IP，避免WAF识别固定模式
		randomIP := getRandomFakeIP()
		for key, value := range cfg.AntiDetection.FakeHeaders.Headers {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" && value != "" {
				// 对IP类头部使用随机IP
				keyLower := strings.ToLower(key)
				if strings.Contains(keyLower, "ip") || strings.Contains(keyLower, "forwarded") {
					req.Header.Set(key, randomIP)
				} else {
					req.Header.Set(key, value)
				}
			}
		}
	}

	// ===== 设置 Host =====
	if host != "" {
		req.Host = host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 限制响应体读取大小，防止大页面导致内存爆炸
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	// 丢弃剩余数据以便连接可以被复用
	io.Copy(io.Discard, resp.Body)

	requestHost := host
	if requestHost == "" {
		requestHost = ip
	}

	contentLength := resp.ContentLength
	if contentLength <= 0 {
		contentLength = int64(len(body))
	}

	return &HttpCustomRequest{
		Host:          requestHost,
		Body:          string(body),
		StatusCode:    resp.StatusCode,
		ContentLen:    int(contentLength),
		Location:      resp.Header.Get("Location"),
		ServerHeader:  resp.Header.Get("Server"),
		XPoweredByVal: resp.Header.Get("X-Powered-By"),
	}, nil
}
