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
			ReadTimeout:    10,
			ConnectTimeout: 10,
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
		ThreadTotal:     6,
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
			Number: 10,
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
			RateLimit: 50,
			Delay: DelayConfig{
				IsStart: true,
				MinMs:   1000,
				MaxMs:   3000,
			},
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
