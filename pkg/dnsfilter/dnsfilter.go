// Package dnsfilter 提供 DNS 反向筛选功能。
//
// 通过对 Host 列表进行 DNS 解析，将解析结果与目标 IP 列表进行网段匹配，
// 按关联度将 Host 分为不同优先级，从而大幅减少无效碰撞请求。
package dnsfilter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MatchMode DNS 匹配模式
type MatchMode int

const (
	// MatchModeSubnet16 /16 网段匹配（宽松，默认）
	MatchModeSubnet16 MatchMode = iota
	// MatchModeSubnet24 /24 网段匹配（严格）
	MatchModeSubnet24
	// MatchModeExact 精确 IP 匹配（最严格）
	MatchModeExact
)

// FilterResult DNS 筛选结果
type FilterResult struct {
	// MatchedHosts DNS 解析到目标 IP 段的 Host（高优先级）
	MatchedHosts []string
	// UnresolvedHosts DNS 解析失败的 Host（中优先级，可能是已下线域名）
	UnresolvedHosts []string
	// UnmatchedHosts DNS 解析到无关 IP 的 Host（低优先级）
	UnmatchedHosts []string

	// 统计信息
	TotalHosts      int
	ResolvedCount   int
	UnresolvedCount int
	MatchedCount    int
	UnmatchedCount  int
	Duration        time.Duration
}

// String 返回筛选结果的摘要信息
func (r *FilterResult) String() string {
	return fmt.Sprintf(
		"DNS筛选完成: 总计 %d 个Host, 解析成功 %d, 解析失败 %d, "+
			"匹配目标IP段 %d, 无关 %d, 耗时 %v",
		r.TotalHosts, r.ResolvedCount, r.UnresolvedCount,
		r.MatchedCount, r.UnmatchedCount, r.Duration.Round(time.Millisecond),
	)
}

// FilterConfig DNS 筛选配置
type FilterConfig struct {
	// MatchMode 匹配模式
	MatchMode MatchMode
	// Concurrency DNS 解析并发数
	Concurrency int
	// DNSTimeout 单次 DNS 解析超时时间
	DNSTimeout time.Duration
	// OutputLog 是否输出日志
	OutputLog bool
}

// DefaultFilterConfig 返回默认筛选配置
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		MatchMode:   MatchModeSubnet16,
		Concurrency: 50,
		DNSTimeout:  5 * time.Second,
		OutputLog:   false,
	}
}

// ExtractIPFromAddr 从 IP 地址字符串中提取纯 IP 部分
// 支持格式: "1.1.1.1", "2.2.2.2:8443", "[::1]:8080", "::1"
func ExtractIPFromAddr(addr string) string {
	// 尝试解析为 host:port 格式
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	// 如果解析失败，可能是纯 IP（无端口）
	// 检查是否是有效的 IP 地址
	if ip := net.ParseIP(addr); ip != nil {
		return addr
	}
	// 最后尝试去掉可能的端口号（简单处理 ip:port 格式）
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		possibleIP := addr[:idx]
		if ip := net.ParseIP(possibleIP); ip != nil {
			return possibleIP
		}
	}
	return addr
}

// buildIPNetSet 根据目标 IP 列表和匹配模式构建网段集合
// 返回用于快速查找的集合
func buildIPNetSet(ipList []string, mode MatchMode) map[string]bool {
	set := make(map[string]bool)
	for _, addr := range ipList {
		pureIP := ExtractIPFromAddr(addr)
		ip := net.ParseIP(pureIP)
		if ip == nil {
			continue
		}

		switch mode {
		case MatchModeExact:
			set[ip.String()] = true
		case MatchModeSubnet24:
			// 提取 /24 网段前缀
			if ipv4 := ip.To4(); ipv4 != nil {
				prefix := fmt.Sprintf("%d.%d.%d", ipv4[0], ipv4[1], ipv4[2])
				set[prefix] = true
			} else {
				// IPv6 使用前 48 位
				set[ip.String()] = true
			}
		case MatchModeSubnet16:
			// 提取 /16 网段前缀
			if ipv4 := ip.To4(); ipv4 != nil {
				prefix := fmt.Sprintf("%d.%d", ipv4[0], ipv4[1])
				set[prefix] = true
			} else {
				set[ip.String()] = true
			}
		}
	}
	return set
}

// matchIP 检查一个 IP 是否匹配目标网段集合
func matchIP(ip net.IP, ipNetSet map[string]bool, mode MatchMode) bool {
	if ip == nil {
		return false
	}

	switch mode {
	case MatchModeExact:
		return ipNetSet[ip.String()]
	case MatchModeSubnet24:
		if ipv4 := ip.To4(); ipv4 != nil {
			prefix := fmt.Sprintf("%d.%d.%d", ipv4[0], ipv4[1], ipv4[2])
			return ipNetSet[prefix]
		}
		return ipNetSet[ip.String()]
	case MatchModeSubnet16:
		if ipv4 := ip.To4(); ipv4 != nil {
			prefix := fmt.Sprintf("%d.%d", ipv4[0], ipv4[1])
			return ipNetSet[prefix]
		}
		return ipNetSet[ip.String()]
	}
	return false
}

// Filter 执行 DNS 反向筛选
//
// 对 hostList 中的每个 Host 进行 DNS 解析，将解析结果与 ipList 中的 IP 进行网段匹配，
// 按关联度将 Host 分为三个优先级：
//   - MatchedHosts: DNS 解析到目标 IP 段的 Host（高优先级，必须碰撞）
//   - UnresolvedHosts: DNS 解析失败的 Host（中优先级，可能是已下线域名，必须碰撞）
//   - UnmatchedHosts: DNS 解析到无关 IP 的 Host（低优先级，可安全过滤）
func Filter(ipList, hostList []string, cfg *FilterConfig) *FilterResult {
	if cfg == nil {
		cfg = DefaultFilterConfig()
	}

	startTime := time.Now()

	result := &FilterResult{
		TotalHosts: len(hostList),
	}

	// 构建目标 IP 网段集合
	ipNetSet := buildIPNetSet(ipList, cfg.MatchMode)

	if cfg.OutputLog {
		modeStr := "未知"
		switch cfg.MatchMode {
		case MatchModeSubnet16:
			modeStr = "/16 网段"
		case MatchModeSubnet24:
			modeStr = "/24 网段"
		case MatchModeExact:
			modeStr = "精确匹配"
		}
		fmt.Printf("DNS筛选开始: %d 个Host, %d 个目标IP, 匹配模式: %s, 并发数: %d\n",
			len(hostList), len(ipList), modeStr, cfg.Concurrency)
	}

	// 并发 DNS 解析
	type resolveResult struct {
		host     string
		matched  bool
		resolved bool
	}

	resultCh := make(chan resolveResult, len(hostList))
	sem := make(chan struct{}, cfg.Concurrency)

	// 自定义 DNS 解析器，使用较短的超时
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: cfg.DNSTimeout,
			}
			// 使用系统默认 DNS
			return d.Dial(network, address)
		},
	}

	var wg sync.WaitGroup
	var resolvedCount int64
	var progressCount int64

	for _, host := range hostList {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 去掉可能的协议前缀和路径
			cleanHost := cleanHostName(h)

			// 如果 host 本身就是 IP 地址，直接匹配
			if ip := net.ParseIP(cleanHost); ip != nil {
				matched := matchIP(ip, ipNetSet, cfg.MatchMode)
				resultCh <- resolveResult{host: h, matched: matched, resolved: true}
				atomic.AddInt64(&resolvedCount, 1)
				atomic.AddInt64(&progressCount, 1)
				return
			}

			// DNS 解析
			ctx, cancel := context.WithTimeout(context.Background(), cfg.DNSTimeout)
			ips, err := resolver.LookupHost(ctx, cleanHost)
			cancel()

			current := atomic.AddInt64(&progressCount, 1)
			if cfg.OutputLog && current%10000 == 0 {
				fmt.Printf("DNS筛选进度: %d/%d\n", current, len(hostList))
			}

			if err != nil || len(ips) == 0 {
				// 解析失败 → 中优先级
				resultCh <- resolveResult{host: h, matched: false, resolved: false}
				return
			}

			atomic.AddInt64(&resolvedCount, 1)

			// 检查解析到的 IP 是否匹配目标网段
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if matchIP(ip, ipNetSet, cfg.MatchMode) {
					resultCh <- resolveResult{host: h, matched: true, resolved: true}
					return
				}
			}

			// 解析成功但不匹配 → 低优先级
			resultCh <- resolveResult{host: h, matched: false, resolved: true}
		}(host)
	}

	// 等待所有解析完成后关闭结果通道
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果
	for r := range resultCh {
		if !r.resolved {
			result.UnresolvedHosts = append(result.UnresolvedHosts, r.host)
			result.UnresolvedCount++
		} else if r.matched {
			result.MatchedHosts = append(result.MatchedHosts, r.host)
			result.MatchedCount++
		} else {
			result.UnmatchedHosts = append(result.UnmatchedHosts, r.host)
			result.UnmatchedCount++
		}
	}

	result.ResolvedCount = int(atomic.LoadInt64(&resolvedCount))
	result.Duration = time.Since(startTime)

	if cfg.OutputLog {
		fmt.Println(result.String())
	}

	return result
}

// GetEffectiveHosts 获取需要碰撞的有效 Host 列表
// 返回 MatchedHosts + UnresolvedHosts（过滤掉无关 Host）
func (r *FilterResult) GetEffectiveHosts() []string {
	hosts := make([]string, 0, len(r.MatchedHosts)+len(r.UnresolvedHosts))
	hosts = append(hosts, r.MatchedHosts...)
	hosts = append(hosts, r.UnresolvedHosts...)
	return hosts
}

// GetAllHostsByPriority 按优先级返回所有 Host
// 顺序: MatchedHosts → UnresolvedHosts → UnmatchedHosts
func (r *FilterResult) GetAllHostsByPriority() []string {
	hosts := make([]string, 0, r.TotalHosts)
	hosts = append(hosts, r.MatchedHosts...)
	hosts = append(hosts, r.UnresolvedHosts...)
	hosts = append(hosts, r.UnmatchedHosts...)
	return hosts
}

// cleanHostName 清理 Host 名称，去掉协议前缀、端口和路径
func cleanHostName(host string) string {
	// 去掉协议前缀
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// 去掉路径
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}

	// 去掉端口（但保留 IPv6 地址中的冒号）
	if !strings.Contains(host, "[") {
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			possibleHost := host[:idx]
			// 确保不是 IPv6 地址
			if !strings.Contains(possibleHost, ":") {
				host = possibleHost
			}
		}
	}

	return strings.TrimSpace(host)
}

// ParseMatchMode 从字符串解析匹配模式
// 支持: "16", "/16", "subnet16" → MatchModeSubnet16
//
//	"24", "/24", "subnet24" → MatchModeSubnet24
//	"exact", "0"            → MatchModeExact
func ParseMatchMode(s string) MatchMode {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "24", "/24", "subnet24":
		return MatchModeSubnet24
	case "exact", "0":
		return MatchModeExact
	default:
		return MatchModeSubnet16
	}
}

// MatchModeString 返回匹配模式的字符串表示
func MatchModeString(mode MatchMode) string {
	switch mode {
	case MatchModeSubnet16:
		return "/16"
	case MatchModeSubnet24:
		return "/24"
	case MatchModeExact:
		return "exact"
	default:
		return "unknown"
	}
}
