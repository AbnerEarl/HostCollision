package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config 全局配置结构体
type Config struct {
	HTTP                       HTTPConfig          `yaml:"http"`
	SimilarityRatio            float64             `yaml:"similarityRatio"`
	ThreadTotal                int                 `yaml:"threadTotal"`
	DataSource                 DataSourceConfig    `yaml:"dataSource"`
	DefaultResultOutput        DefaultResultOutput `yaml:"defaultResultOutput"`
	IsOutputErrorLog           bool                `yaml:"isOutputErrorLog"`
	CollisionSuccessStatusCode string              `yaml:"collisionSuccessStatusCode"`
	Blacklists                 BlacklistsConfig    `yaml:"blacklists"`
	DataSample                 DataSampleConfig    `yaml:"dataSample"`
	AntiDetection              AntiDetectionConfig `yaml:"antiDetection"`
	Optimization               OptimizationConfig  `yaml:"optimization"`
}

// OptimizationConfig 优化策略配置
type OptimizationConfig struct {
	// EnableDNSFilter 是否启用 DNS 反向筛选（默认开启）
	EnableDNSFilter bool `yaml:"enableDNSFilter"`
	// DNSMatchMode DNS 匹配模式: "16"(默认/16网段), "24"(/24网段), "exact"(精确匹配)
	DNSMatchMode string `yaml:"dnsMatchMode"`
	// DNSConcurrency DNS 解析并发数
	DNSConcurrency int `yaml:"dnsConcurrency"`
	// EnableResponseElimination 是否启用响应快速排除（默认开启）
	EnableResponseElimination bool `yaml:"enableResponseElimination"`
	// ResponseSampleSize 响应快速排除的采样 Host 数量（默认50）
	ResponseSampleSize int `yaml:"responseSampleSize"`
	// FullScan 是否强制全量扫描（忽略所有优化策略）
	FullScan bool `yaml:"fullScan"`
	// AutoFullScanThreshold 自动全量扫描阈值（预估碰撞组合数低于此值时自动全量扫描）
	// 默认值基于 1 小时可完成的碰撞量计算
	AutoFullScanThreshold int64 `yaml:"autoFullScanThreshold"`

	// ===== 方案一: HEAD 预筛选 =====
	// EnableHEADPreFilter 是否启用 HEAD 预筛选（默认开启）
	// 对每个 IP 先发送 HEAD 请求获取响应头指纹，只有指纹与基准不同的 Host 才进入 GET 碰撞
	// 注意: 如果服务不支持 HEAD 方法（返回 405/501），会自动回退到 GET 碰撞
	EnableHEADPreFilter bool `yaml:"enableHEADPreFilter"`

	// ===== 方案二: TLS 证书 SAN 提取 =====
	// EnableTLSScan 是否启用 TLS 证书 SAN 提取（默认开启）
	// 对 HTTPS 端口做 TLS 握手，提取证书中的域名列表，标记为最高优先级
	EnableTLSScan bool `yaml:"enableTLSScan"`
	// TLSScanConcurrency TLS 扫描并发数
	TLSScanConcurrency int `yaml:"tlsScanConcurrency"`

	// ===== 方案三: 基准指纹缓存 + 快速比对 =====
	// EnableFingerprintCache 是否启用基准指纹缓存快速比对（默认开启）
	// 使用 hash 指纹做快速比对，只有 hash 不同时才做编辑距离计算
	EnableFingerprintCache bool `yaml:"enableFingerprintCache"`

	// ===== 方案五: 自适应分阶段采样 =====
	// EnableAdaptiveSampling 是否启用自适应分阶段采样（默认开启）
	// 先采样少量 Host，逐步增加采样数量，对明显无效的 IP 更快跳过
	EnableAdaptiveSampling bool `yaml:"enableAdaptiveSampling"`

	// ===== 方案六: 万能响应IP检测 =====
	// EnableCatchAllDetection 是否启用万能响应IP检测（默认开启）
	// 当一个 IP 对大量不同 Host 都碰撞成功时，判定为"万能响应"IP（默认虚拟主机/通配符配置），
	// 自动清除该 IP 的所有碰撞结果并跳过剩余 Host
	EnableCatchAllDetection bool `yaml:"enableCatchAllDetection"`
	// CatchAllThreshold 万能响应IP判定阈值（默认10）
	// 当一个 IP+协议 维度碰撞成功的 Host 数量超过此值时，判定为万能响应IP
	CatchAllThreshold int `yaml:"catchAllThreshold"`
}

// HTTPConfig HTTP 请求相关配置
type HTTPConfig struct {
	ReadTimeout      int             `yaml:"readTimeout"`
	ConnectTimeout   int             `yaml:"connectTimeout"`
	Proxy            ProxyConfig     `yaml:"proxy"`
	ProxyPool        ProxyPoolConfig `yaml:"proxyPool"`
	ScanProtocol     ScanProtocol    `yaml:"scanProtocol"`
	ErrorHost        string          `yaml:"errorHost"`
	RelativeHostName string          `yaml:"relativeHostName"`
}

// ProxyConfig 单一代理配置
type ProxyConfig struct {
	IsStart  bool   `yaml:"isStart"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ProxyPoolConfig 代理池配置
type ProxyPoolConfig struct {
	IsStart  bool   `yaml:"isStart"`
	FilePath string `yaml:"filePath"`
}

// ScanProtocol 扫描协议配置
type ScanProtocol struct {
	IsScanHTTP  bool `yaml:"isScanHttp"`
	IsScanHTTPS bool `yaml:"isScanHttps"`
}

// DataSourceConfig 数据源配置
type DataSourceConfig struct {
	IPFilePath   string `yaml:"ipFilePath"`
	HostFilePath string `yaml:"hostFilePath"`
}

// DefaultResultOutput 默认结果输出配置
type DefaultResultOutput struct {
	IsOutputCSV bool `yaml:"isOutputCsv"`
	IsOutputTXT bool `yaml:"isOutputTxt"`
}

// BlacklistsConfig 黑名单配置
type BlacklistsConfig struct {
	HTTPServices   []string `yaml:"httpServices"`
	HTTPBodies     []string `yaml:"httpBodies"`
	HTTPXPoweredBy []string `yaml:"httpXPoweredBy"`
}

// DataSampleConfig 数据样本配置
type DataSampleConfig struct {
	Number int `yaml:"number"`
}

// AntiDetectionConfig 防检测/防封禁配置
type AntiDetectionConfig struct {
	// User-Agent 随机化
	RandomUA bool `yaml:"randomUA"`
	// Header 伪造（Bypass WAF）
	FakeHeaders FakeHeadersConfig `yaml:"fakeHeaders"`
	// 速率控制（每秒最大请求数, 0表示不限制）
	RateLimit int `yaml:"rateLimit"`
	// 延迟扫描（请求间隔，单位毫秒）
	Delay DelayConfig `yaml:"delay"`
}

// FakeHeadersConfig Header 伪造配置
type FakeHeadersConfig struct {
	IsStart bool              `yaml:"isStart"`
	Headers map[string]string `yaml:"headers"`
}

// DelayConfig 延迟扫描配置
type DelayConfig struct {
	IsStart bool `yaml:"isStart"`
	MinMs   int  `yaml:"minMs"`
	MaxMs   int  `yaml:"maxMs"`
}

var (
	instance *Config
	once     sync.Once
)

// GetInstance 获取配置单例（从配置文件加载，命令行模式使用）
func GetInstance() *Config {
	once.Do(func() {
		instance = &Config{}
		if err := instance.load(); err != nil {
			fmt.Printf("error: 加载配置文件失败: %v\n", err)
			os.Exit(1)
		}
	})
	return instance
}

// SetInstance 设置配置单例（库模式调用时使用，允许外部传入配置）
func SetInstance(cfg *Config) {
	once.Do(func() {})
	instance = cfg
}

// ResetInstance 重置配置单例（允许重新初始化，用于测试或多次调用）
func ResetInstance() {
	once = sync.Once{}
	instance = nil
}

// DefaultConfig 返回一套合理的默认配置
// 外部调用方可以基于此配置进行修改，无需配置文件即可使用
func DefaultConfig() *Config {
	return &Config{
		HTTP: HTTPConfig{
			ReadTimeout:    8,
			ConnectTimeout: 5,
			Proxy: ProxyConfig{
				IsStart: false,
				Host:    "127.0.0.1",
				Port:    8080,
			},
			ProxyPool: ProxyPoolConfig{
				IsStart: false,
			},
			ScanProtocol: ScanProtocol{
				IsScanHTTP:  true,
				IsScanHTTPS: true,
			},
			ErrorHost:        "error.hchostjwdlh666666.com",
			RelativeHostName: "q1w2e3sr4.",
		},
		SimilarityRatio: 0.7,
		ThreadTotal:     30,
		DataSource: DataSourceConfig{
			IPFilePath:   "./dataSource/ipList.txt",
			HostFilePath: "./dataSource/hostList.txt",
		},
		DefaultResultOutput: DefaultResultOutput{
			IsOutputCSV: true,
			IsOutputTXT: true,
		},
		IsOutputErrorLog:           true,
		CollisionSuccessStatusCode: "200,301,302,404",
		Blacklists: BlacklistsConfig{
			HTTPServices: []string{"waf"},
			HTTPBodies: []string{
				`document.getElementById("mainFrame").src="http://batit.aliyun.com/alww.html";`,
				"服务器安全狗防护验证页面",
				"该网站暂时无法进行访问，可能由以下原因导致",
				"本网站尚未进行备案",
				"重获备案号后，如何恢复访问",
				"您的请求在Web服务器中没有找到对应的站点",
				"检查是否已经绑定到对应站点，若确认已绑定，请尝试重载Web服务",
				"您没有将此域名或IP绑定到对应站点",
				"若您使用了CDN产品，请尝试清除CDN缓存",
				"该访问行为触发了WAF安全策略",
				"请将本页面截图以及您正访问的链接地址提交给信息安全中心以需求帮助",
			},
			HTTPXPoweredBy: []string{"waf"},
		},
		DataSample: DataSampleConfig{
			Number: 3,
		},
		AntiDetection: AntiDetectionConfig{
			RandomUA: true,
			FakeHeaders: FakeHeadersConfig{
				IsStart: true,
				Headers: map[string]string{
					"X-Forwarded-For":  "127.0.0.1",
					"X-Real-IP":        "127.0.0.1",
					"X-Originating-IP": "127.0.0.1",
					"X-Client-IP":      "127.0.0.1",
					"CF-Connecting-IP": "127.0.0.1",
				},
			},
			RateLimit: 200,
			Delay: DelayConfig{
				IsStart: true,
				MinMs:   50,
				MaxMs:   200,
			},
		},
		Optimization: OptimizationConfig{
			EnableDNSFilter:           true,
			DNSMatchMode:              "16",
			DNSConcurrency:            100,
			EnableResponseElimination: true,
			ResponseSampleSize:        50,
			FullScan:                  false,
			// 默认阈值: 按200QPS计算，1小时可完成 200*3600=720000 次请求
			AutoFullScanThreshold: 720000,
			// 方案一: HEAD 预筛选（默认开启）
			EnableHEADPreFilter: true,
			// 方案二: TLS 证书 SAN 提取（默认开启）
			EnableTLSScan:      true,
			TLSScanConcurrency: 50,
			// 方案三: 基准指纹缓存（默认开启）
			EnableFingerprintCache: true,
			// 方案五: 自适应分阶段采样（默认开启）
			EnableAdaptiveSampling: true,
			// 方案六: 万能响应IP检测（默认开启）
			EnableCatchAllDetection: true,
			CatchAllThreshold:       10,
		},
	}
}

// NewConfigFromYAML 从 YAML 字节数据创建配置
// 适用于调用方自行管理配置数据的场景
func NewConfigFromYAML(data []byte) (*Config, error) {
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析YAML配置数据失败: %w", err)
	}
	return cfg, nil
}

// NewConfigFromFile 从 YAML 文件路径创建配置
func NewConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败 %s: %w", path, err)
	}
	return NewConfigFromYAML(data)
}

// load 加载配置文件（内部使用）
func (c *Config) load() error {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败 %s: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	return nil
}

// getConfigPath 获取配置文件路径
func getConfigPath() string {
	execDir, _ := os.Getwd()
	paths := []string{
		execDir + "/resource/config.yml",
		execDir + "/config.yml",
		"./resource/config.yml",
		"./config.yml",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}

// GetResourcePath 获取资源目录路径
func GetResourcePath() string {
	execDir, _ := os.Getwd()
	paths := []string{
		execDir + "/resource",
		"./resource",
	}
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return paths[0]
}

// GetHTTPServiceBlacklists 获取 HTTP Service 黑名单(小写)
func (c *Config) GetHTTPServiceBlacklists() []string {
	var result []string
	for _, s := range c.Blacklists.HTTPServices {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, strings.ToLower(s))
		}
	}
	return result
}

// GetHTTPBodyBlacklists 获取 HTTP Body 黑名单(小写)
func (c *Config) GetHTTPBodyBlacklists() []string {
	var result []string
	for _, s := range c.Blacklists.HTTPBodies {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, strings.ToLower(s))
		}
	}
	return result
}

// GetHTTPXPoweredByBlacklists 获取 HTTP X-Powered-By 黑名单(小写)
func (c *Config) GetHTTPXPoweredByBlacklists() []string {
	var result []string
	for _, s := range c.Blacklists.HTTPXPoweredBy {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, strings.ToLower(s))
		}
	}
	return result
}

// LoadProxyPool 从文件加载代理池列表
// 文件格式: 每行一个代理地址，支持以下格式:
//
//	http://ip:port
//	http://user:pass@ip:port
//	socks5://ip:port
//	socks5://user:pass@ip:port
//	ip:port (默认视为http代理)
func LoadProxyPool(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开代理池文件失败 %s: %w", filePath, err)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		proxies = append(proxies, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取代理池文件失败: %w", err)
	}

	return proxies, nil
}
