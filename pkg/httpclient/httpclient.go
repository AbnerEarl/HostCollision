package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/diffpage"
	"github.com/AbnerEarl/HostCollision/pkg/helpers"
)

// ========== 抑制 Go 标准库无关日志 ==========

// filterWriter 过滤特定日志的 io.Writer
// Go 标准库 net/http 的 Transport 在空闲连接上收到未请求的响应时，
// 会通过 log.Printf 输出 "Unsolicited response received on idle HTTP channel" 日志，
// 这类日志不是错误，但会污染标准输出，影响日志可读性。
type filterWriter struct {
	original io.Writer
	filters  [][]byte // 需要过滤的日志关键词
}

// Write 实现 io.Writer 接口，过滤包含特定关键词的日志
func (fw *filterWriter) Write(p []byte) (n int, err error) {
	for _, filter := range fw.filters {
		if bytes.Contains(p, filter) {
			// 返回成功写入的字节数（欺骗 log 包认为写入成功），但实际丢弃
			return len(p), nil
		}
	}
	return fw.original.Write(p)
}

// suppressLogOnce 确保日志过滤只初始化一次
var suppressLogOnce sync.Once

// SuppressUnsolicitedResponseLog 抑制 Go 标准库 net/http 输出的无关日志
// 主要过滤 "Unsolicited response received on idle HTTP channel" 日志
// 该日志在使用 HTTP Keep-Alive 连接池时，服务端主动关闭连接或推送异常响应时触发
// 这不是程序错误，只是 Go 标准库的一个信息性输出
func SuppressUnsolicitedResponseLog() {
	suppressLogOnce.Do(func() {
		log.SetOutput(&filterWriter{
			original: log.Writer(),
			filters: [][]byte{
				[]byte("Unsolicited response received on idle HTTP channel"),
			},
		})
	})
}

func init() {
	// 自动抑制 Go 标准库 net/http 的无关日志
	SuppressUnsolicitedResponseLog()
}

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
		// 增大 MaxIdleConnsPerHost 以提升同一 IP 的连接复用率
		DisableKeepAlives:   false,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     60 * time.Second,
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

// ========== 编码检测与转换 ==========

// detectAndConvertToUTF8 检测响应体编码并转换为 UTF-8
// 检测优先级: Content-Type header > HTML meta charset > 自动检测
// 如果已经是 UTF-8 或检测/转换失败，返回原始内容
//
// 关键修复：某些 GBK/GB2312 编码的字节序列恰好也是合法的 UTF-8 多字节序列，
// 导致 isValidUTF8 误判为 UTF-8 而跳过转换。修复策略：
// 1. 当 charset.DetermineEncoding 检测到非 UTF-8 编码时，无论 certain 值如何，都尝试转换
// 2. 转换后验证结果是否比原始内容更合理（包含更多有效中文字符）
// 3. 只有在完全无法确定编码且内容是合法 UTF-8 时才跳过转换
func detectAndConvertToUTF8(body []byte, contentType string) string {
	// 如果内容为空，直接返回
	if len(body) == 0 {
		return ""
	}

	// 尝试从 Content-Type header 和 HTML meta 标签中确定编码
	// charset.DetermineEncoding 会综合考虑 Content-Type 和 HTML 内容
	encoding, encodingName, certain := charset.DetermineEncoding(body, contentType)

	// 如果无法确定编码，直接返回原始字符串
	if encoding == nil {
		return string(body)
	}

	// 判断检测到的编码是否为 UTF-8 系列
	encodingNameLower := strings.ToLower(encodingName)
	isUTF8Encoding := encodingNameLower == "utf-8" || encodingNameLower == "utf8"

	// 如果确定是 UTF-8 编码，直接返回
	if certain && isUTF8Encoding {
		return string(body)
	}

	// 如果检测到非 UTF-8 编码（如 GBK/GB2312/GB18030/Shift_JIS 等），
	// 无论 certain 值如何，都尝试转换。
	// 这是因为 charset.DetermineEncoding 基于 Content-Type 和 HTML meta 标签的检测
	// 通常比纯字节序列分析更可靠。
	if !isUTF8Encoding {
		reader := transform.NewReader(bytes.NewReader(body), encoding.NewDecoder())
		decoded, err := io.ReadAll(reader)
		if err != nil {
			// 转换失败，尝试 GBK 解码作为备选
			gbkDecoded := tryGBKDecode(body)
			if gbkDecoded != "" && countCJKChars(gbkDecoded) > 0 {
				return gbkDecoded
			}
			return string(body)
		}
		decodedStr := string(decoded)
		decodedCJK := countCJKChars(decodedStr)
		originalCJK := countCJKChars(string(body))

		// 如果检测到的编码解码后产生了有效 CJK 字符，且比原始内容多，说明解码正确
		if decodedCJK > 0 && decodedCJK >= originalCJK {
			return decodedStr
		}

		// 检测到的编码解码后没有产生 CJK 字符（如 windows-1252 解码 GBK 内容）
		// 额外尝试 GBK 解码，看是否能产生有效中文
		if decodedCJK == 0 && originalCJK == 0 {
			// 检查原始内容是否包含非 ASCII 字节（可能是 GBK 编码）
			hasHighBytes := false
			for _, b := range body {
				if b >= 0x80 {
					hasHighBytes = true
					break
				}
			}
			if hasHighBytes {
				gbkDecoded := tryGBKDecode(body)
				if gbkDecoded != "" && countCJKChars(gbkDecoded) > 0 {
					return gbkDecoded
				}
			}
		}

		// 如果解码后 CJK 字符反而减少了，可能是误判，返回原始内容
		if decodedCJK < originalCJK {
			return string(body)
		}

		// 其他情况（如纯 ASCII 内容），返回解码结果
		return decodedStr
	}

	// 检测到 UTF-8 但不确定（certain=false）
	// 需要区分两种情况：
	// A) 真正的 UTF-8 内容（meta 标签声明了 utf-8，或内容本身就是 UTF-8 中文）
	// B) GBK 内容恰好通过了 UTF-8 合法性检查（极少数 GBK 字节序列恰好是合法 UTF-8）
	if isValidUTF8(body) {
		utf8Str := string(body)
		utf8CJK := countCJKChars(utf8Str)

		// 策略1：如果 HTML meta 标签明确声明了 charset=utf-8，直接信任
		// charset.DetermineEncoding 已经检测到 utf-8（来自 meta 标签），直接返回
		if hasUTF8MetaCharset(body) {
			return utf8Str
		}

		// 策略2：如果原始 UTF-8 内容已经包含 CJK 字符，说明它确实是 UTF-8 编码的中文内容
		// 不应该再尝试 GBK 解码，因为 GBK 解码 UTF-8 中文时会产生"膨胀"的假 CJK 字符
		// （3字节 UTF-8 中文 → 被拆成 2 个 GBK 字符，部分恰好落在 CJK 范围）
		if utf8CJK > 0 {
			return utf8Str
		}

		// 策略3：原始内容没有 CJK 字符，但包含非 ASCII 字节
		// 这种情况可能是 GBK 编码的内容恰好通过了 UTF-8 合法性检查
		hasNonASCII := false
		for _, b := range body {
			if b >= 0x80 {
				hasNonASCII = true
				break
			}
		}
		if hasNonASCII {
			gbkDecoded := tryGBKDecode(body)
			if gbkDecoded != "" {
				gbkCJK := countCJKChars(gbkDecoded)
				// 原始 UTF-8 没有 CJK 字符，但 GBK 解码后有 → 说明原始内容实际是 GBK 编码
				if gbkCJK > 0 {
					if utf8.ValidString(gbkDecoded) {
						return gbkDecoded
					}
				}
			}
		}
		return utf8Str
	}

	// 内容不是合法 UTF-8，尝试转换
	reader := transform.NewReader(bytes.NewReader(body), encoding.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		// 转换失败，再尝试 GBK
		gbkDecoded := tryGBKDecode(body)
		if gbkDecoded != "" {
			return gbkDecoded
		}
		return string(body)
	}

	return string(decoded)
}

// hasUTF8MetaCharset 检查 HTML 内容中是否有 meta 标签明确声明了 UTF-8 编码
// 支持两种常见格式：
//   - <meta charset="utf-8">
//   - <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
func hasUTF8MetaCharset(body []byte) bool {
	// 只检查前 1024 字节（meta 标签通常在 head 的开头部分）
	checkLen := 1024
	if len(body) < checkLen {
		checkLen = len(body)
	}
	head := strings.ToLower(string(body[:checkLen]))

	// 检查 <meta charset="utf-8"> 或 <meta charset='utf-8'>
	if strings.Contains(head, `charset="utf-8"`) || strings.Contains(head, `charset='utf-8'`) {
		return true
	}
	// 检查 charset=utf-8（无引号，如在 Content-Type 中）
	if strings.Contains(head, "charset=utf-8") {
		return true
	}
	return false
}

// tryGBKDecode 尝试将字节序列按 GBK 编码解码为 UTF-8 字符串
// 如果解码失败或结果无效，返回空字符串
func tryGBKDecode(body []byte) string {
	reader := transform.NewReader(bytes.NewReader(body), simplifiedchinese.GBK.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return ""
	}
	result := string(decoded)
	// 验证解码结果是否为合法 UTF-8
	if !utf8.ValidString(result) {
		return ""
	}
	return result
}

// countCJKChars 统计字符串中 CJK（中日韩）字符的数量
// 用于编码转换后的验证：正确的编码转换应该产生更多有效的 CJK 字符
func countCJKChars(s string) int {
	count := 0
	for _, r := range s {
		// CJK 统一汉字
		if r >= 0x4E00 && r <= 0x9FFF {
			count++
			continue
		}
		// CJK 扩展 A
		if r >= 0x3400 && r <= 0x4DBF {
			count++
			continue
		}
		// 日文平假名和片假名
		if r >= 0x3040 && r <= 0x30FF {
			count++
			continue
		}
		// 韩文音节
		if r >= 0xAC00 && r <= 0xD7AF {
			count++
			continue
		}
		// CJK 兼容汉字
		if r >= 0xF900 && r <= 0xFAFF {
			count++
			continue
		}
	}
	return count
}

// isValidUTF8 检查字节序列是否为合法的 UTF-8 编码
// 通过检测是否包含典型的非 UTF-8 乱码特征来判断
func isValidUTF8(data []byte) bool {
	// 统计无效 UTF-8 字节的比例
	invalidCount := 0
	i := 0
	for i < len(data) {
		if data[i] < 0x80 {
			// ASCII 字符
			i++
			continue
		}

		// 检查多字节 UTF-8 序列
		var seqLen int
		switch {
		case data[i]&0xE0 == 0xC0:
			seqLen = 2
		case data[i]&0xF0 == 0xE0:
			seqLen = 3
		case data[i]&0xF8 == 0xF0:
			seqLen = 4
		default:
			invalidCount++
			i++
			continue
		}

		if i+seqLen > len(data) {
			invalidCount++
			i++
			continue
		}

		valid := true
		for j := 1; j < seqLen; j++ {
			if data[i+j]&0xC0 != 0x80 {
				valid = false
				break
			}
		}

		if valid {
			i += seqLen
		} else {
			invalidCount++
			i++
		}
	}

	// 如果无效字节超过非 ASCII 字节的 10%，认为不是 UTF-8
	if invalidCount > 0 {
		nonASCII := 0
		for _, b := range data {
			if b >= 0x80 {
				nonASCII++
			}
		}
		if nonASCII > 0 && float64(invalidCount)/float64(nonASCII) > 0.1 {
			return false
		}
	}

	return true
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
// 优先从原始 Body 中提取 title，如果提取不到再从 AppBody() 中提取
// 修复: 当响应包含 Location 跳转头（301/302）时，AppBody() 返回的是 URL 字符串而非 HTML，
// 导致正则匹配不到 <title> 标签，Title 为空
func (r *HttpCustomRequest) Title() string {
	if !r.titleComputed {
		// 优先从原始响应体提取 title（即使是重定向响应，Body 中也可能包含 HTML）
		r.cachedTitle = helpers.GetBodyTitle(r.Body)
		// 如果原始 Body 中没有 title，再尝试从 AppBody() 中提取
		if r.cachedTitle == "" {
			r.cachedTitle = helpers.GetBodyTitle(r.AppBody())
		}
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
// 支持最多跟随 3 次重定向，跟随时保持原始 Host 头
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

	// 最大重定向跟随次数
	const maxRedirects = 3

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.HTTP.ReadTimeout+cfg.HTTP.ConnectTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				// 超过最大重定向次数，停止跟随，返回最后一个响应
				return http.ErrUseLastResponse
			}
			// 跟随重定向时保持原始 Host 头
			// 这对 Host 碰撞场景很重要：重定向后仍然需要使用碰撞的 Host
			if len(via) > 0 && via[0].Host != "" {
				req.Host = via[0].Host
			}
			return nil
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

	// 编码检测与转换：将非 UTF-8 编码（如 GBK/GB2312）的响应体转换为 UTF-8
	contentTypeHeader := resp.Header.Get("Content-Type")
	bodyStr := detectAndConvertToUTF8(body, contentTypeHeader)

	return &HttpCustomRequest{
		Host:          requestHost,
		Body:          bodyStr,
		StatusCode:    resp.StatusCode,
		ContentLen:    int(contentLength),
		Location:      resp.Header.Get("Location"),
		ServerHeader:  resp.Header.Get("Server"),
		XPoweredByVal: resp.Header.Get("X-Powered-By"),
	}, nil
}

// HeadFingerprint HEAD 请求的轻量级响应指纹
// 仅包含响应头信息，不包含 Body，用于快速预筛选
type HeadFingerprint struct {
	StatusCode    int    // HTTP 状态码
	ContentLength int64  // Content-Length 头（-1 表示未设置）
	ServerHeader  string // Server 头
	Location      string // Location 头
	ContentType   string // Content-Type 头
	XPoweredBy    string // X-Powered-By 头
}

// String 返回指纹的字符串表示（用于比对）
func (f *HeadFingerprint) String() string {
	return fmt.Sprintf("%d|%d|%s|%s|%s",
		f.StatusCode, f.ContentLength, f.ServerHeader, f.Location, f.ContentType)
}

// SendHTTPHeadRequest 发送 HTTP HEAD 请求（轻量级，仅获取响应头）
// HEAD 请求不返回 Body，速度比 GET 快 5-10 倍，用于快速预筛选
// 支持: UA 随机化、Header 伪造、代理池轮换、速率限制、延迟扫描、连接池复用
//
// 注意: 并非所有服务都支持 HEAD 方法，调用方需要处理 405 Method Not Allowed 等情况
func SendHTTPHeadRequest(protocol, ip, host string) (*HeadFingerprint, error) {
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

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HEAD请求失败: %w", err)
	}

	// ===== 设置请求头（与 GET 请求保持一致的指纹）=====
	req.Header.Set("User-Agent", userAgent)
	if cfg.AntiDetection.RandomUA {
		req.Header.Set("Accept", getRandomAccept())
		req.Header.Set("Accept-Language", getRandomAcceptLanguage())
	} else {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7")
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")

	// ===== Header 伪造（Bypass WAF）=====
	if cfg.AntiDetection.FakeHeaders.IsStart {
		randomIP := getRandomFakeIP()
		for key, value := range cfg.AntiDetection.FakeHeaders.Headers {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" && value != "" {
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
		return nil, fmt.Errorf("HEAD请求失败: %w", err)
	}
	defer resp.Body.Close()
	// HEAD 请求不应有 Body，但仍需丢弃以便连接复用
	io.Copy(io.Discard, resp.Body)

	return &HeadFingerprint{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ServerHeader:  resp.Header.Get("Server"),
		Location:      resp.Header.Get("Location"),
		ContentType:   resp.Header.Get("Content-Type"),
		XPoweredBy:    resp.Header.Get("X-Powered-By"),
	}, nil
}
