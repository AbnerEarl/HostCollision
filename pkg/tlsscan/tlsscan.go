// Package tlsscan 提供 TLS 证书 SAN（Subject Alternative Name）提取功能。
//
// 通过对目标 IP 的 HTTPS 端口进行 TLS 握手，提取服务器证书中的域名列表，
// 将这些域名与 Host 列表做交集，标记为最高优先级碰撞目标。
// 这是一种零漏报的优化手段，因为证书中的域名是服务器明确声明支持的。
package tlsscan

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ScanConfig TLS 扫描配置
type ScanConfig struct {
	// Concurrency 并发握手数量
	Concurrency int
	// Timeout 单次 TLS 握手超时时间
	Timeout time.Duration
	// OutputLog 是否输出日志
	OutputLog bool
}

// DefaultScanConfig 返回默认扫描配置
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Concurrency: 30,
		Timeout:     8 * time.Second,
		OutputLog:   false,
	}
}

// ScanResult TLS 扫描结果
type ScanResult struct {
	// CertDomains 从所有 IP 的证书中提取到的域名集合（去重）
	CertDomains []string
	// IPCertMap 每个 IP 对应的证书域名列表
	IPCertMap map[string][]string
	// MatchedHosts 与 Host 列表匹配的域名（最高优先级 P0）
	MatchedHosts []string
	// ScannedCount 成功扫描的 IP 数量
	ScannedCount int
	// FailedCount 扫描失败的 IP 数量
	FailedCount int
	// Duration 扫描耗时
	Duration time.Duration
}

// String 返回扫描结果的可读字符串
func (r *ScanResult) String() string {
	return fmt.Sprintf(
		"TLS证书扫描: 成功%d, 失败%d, 提取域名%d, 匹配Host%d, 耗时%v",
		r.ScannedCount, r.FailedCount, len(r.CertDomains),
		len(r.MatchedHosts), r.Duration.Round(time.Millisecond),
	)
}

// extractIPAndPort 从地址字符串中提取 IP 和端口
// 支持格式: "1.1.1.1", "2.2.2.2:8443", "[::1]:8080"
// 返回: (ip, port)，如果没有端口则 port 为空字符串
func extractIPAndPort(addr string) (string, string) {
	// 尝试解析为 host:port 格式
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return host, port
	}
	// 如果解析失败，可能是纯 IP（无端口）
	if ip := net.ParseIP(addr); ip != nil {
		return addr, ""
	}
	// 最后尝试去掉可能的端口号
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		possibleIP := addr[:idx]
		if ip := net.ParseIP(possibleIP); ip != nil {
			return possibleIP, addr[idx+1:]
		}
	}
	return addr, ""
}

// tlsHandshake 对单个 IP:端口 执行 TLS 握手，提取证书中的域名
// 返回域名列表和可能的错误
func tlsHandshake(ip, port string, timeout time.Duration) ([]string, error) {
	addr := net.JoinHostPort(ip, port)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS握手失败 %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("无证书 %s", addr)
	}

	// 提取所有证书中的域名（去重）
	domainSet := make(map[string]bool)
	for _, cert := range certs {
		// SAN 域名
		for _, dns := range cert.DNSNames {
			dns = strings.TrimSpace(strings.ToLower(dns))
			if dns != "" {
				domainSet[dns] = true
			}
		}
		// CN（Common Name）
		cn := strings.TrimSpace(strings.ToLower(cert.Subject.CommonName))
		if cn != "" && net.ParseIP(cn) == nil {
			domainSet[cn] = true
		}
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	return domains, nil
}

// ScanIPs 对 IP 列表执行 TLS 证书扫描
// 提取所有 IP 的 HTTPS 证书中的域名，并与 hostList 做匹配
func ScanIPs(ipList []string, hostList []string, cfg *ScanConfig) *ScanResult {
	if cfg == nil {
		cfg = DefaultScanConfig()
	}

	startTime := time.Now()

	result := &ScanResult{
		IPCertMap: make(map[string][]string),
	}

	// 构建 Host 集合（小写，用于快速查找）
	hostSet := make(map[string]bool, len(hostList))
	for _, h := range hostList {
		hostSet[strings.TrimSpace(strings.ToLower(h))] = true
	}

	// 确定每个 IP 需要扫描的端口
	type scanTarget struct {
		ip   string
		port string
		orig string // 原始地址
	}

	var targets []scanTarget
	seenTargets := make(map[string]bool) // 去重

	for _, addr := range ipList {
		ip, port := extractIPAndPort(addr)
		if ip == "" {
			continue
		}

		if port != "" {
			// 带端口的 IP，直接扫描该端口
			key := ip + ":" + port
			if !seenTargets[key] {
				seenTargets[key] = true
				targets = append(targets, scanTarget{ip: ip, port: port, orig: addr})
			}
		} else {
			// 纯 IP，默认扫描 443 端口
			key := ip + ":443"
			if !seenTargets[key] {
				seenTargets[key] = true
				targets = append(targets, scanTarget{ip: ip, port: "443", orig: addr})
			}
		}
	}

	if len(targets) == 0 {
		result.Duration = time.Since(startTime)
		return result
	}

	// 并发 TLS 握手
	type handshakeResult struct {
		orig    string
		domains []string
		err     error
	}

	resultCh := make(chan handshakeResult, len(targets))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target scanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			domains, err := tlsHandshake(target.ip, target.port, cfg.Timeout)
			resultCh <- handshakeResult{
				orig:    target.orig,
				domains: domains,
				err:     err,
			}
		}(t)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果
	allDomainSet := make(map[string]bool)
	matchedHostSet := make(map[string]bool)

	for hr := range resultCh {
		if hr.err != nil {
			result.FailedCount++
			if cfg.OutputLog {
				fmt.Printf("info: TLS扫描 %s 失败: %v\n", hr.orig, hr.err)
			}
			continue
		}

		result.ScannedCount++
		result.IPCertMap[hr.orig] = hr.domains

		for _, domain := range hr.domains {
			allDomainSet[domain] = true

			// 精确匹配
			if hostSet[domain] {
				matchedHostSet[domain] = true
				continue
			}

			// 通配符匹配: *.example.com 匹配 sub.example.com
			if strings.HasPrefix(domain, "*.") {
				suffix := domain[1:] // ".example.com"
				for h := range hostSet {
					if strings.HasSuffix(h, suffix) && !strings.Contains(h[:len(h)-len(suffix)], ".") {
						matchedHostSet[h] = true
					}
				}
			}
		}
	}

	// 转换结果
	result.CertDomains = make([]string, 0, len(allDomainSet))
	for d := range allDomainSet {
		result.CertDomains = append(result.CertDomains, d)
	}

	result.MatchedHosts = make([]string, 0, len(matchedHostSet))
	for h := range matchedHostSet {
		result.MatchedHosts = append(result.MatchedHosts, h)
	}

	result.Duration = time.Since(startTime)

	if cfg.OutputLog {
		fmt.Println(result.String())
	}

	return result
}
