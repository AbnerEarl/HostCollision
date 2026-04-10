package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AbnerEarl/HostCollision/pkg/collision"
	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/helpers"
	"github.com/AbnerEarl/HostCollision/pkg/httpclient"
	"github.com/AbnerEarl/HostCollision/pkg/progress"
)

func main() {
	// 基本信息输出
	fmt.Println(basicInformationOutput())

	// 解析命令行参数
	opts := parseFlags()

	// 处理 help
	if opts.help {
		flag.Usage()
		os.Exit(0)
	}

	// 加载配置
	cfg := config.GetInstance()

	// 命令行参数覆盖配置文件参数
	if opts.collisionSuccessStatusCode != "" {
		cfg.CollisionSuccessStatusCode = opts.collisionSuccessStatusCode
	}
	if opts.dataSampleNumber >= 0 {
		cfg.DataSample.Number = opts.dataSampleNumber
	}
	if opts.rateLimit >= 0 {
		cfg.AntiDetection.RateLimit = opts.rateLimit
	}
	if opts.delayMin >= 0 && opts.delayMax >= 0 {
		cfg.AntiDetection.Delay.IsStart = true
		cfg.AntiDetection.Delay.MinMs = opts.delayMin
		cfg.AntiDetection.Delay.MaxMs = opts.delayMax
	}
	if opts.proxyPoolFile != "" {
		cfg.HTTP.ProxyPool.IsStart = true
		cfg.HTTP.ProxyPool.FilePath = opts.proxyPoolFile
	}
	if opts.randomUA != "" {
		cfg.AntiDetection.RandomUA = strings.TrimSpace(strings.ToLower(opts.randomUA)) != "false"
	}

	// 获取各项配置参数（命令行优先级高于配置文件）
	scanProtocols := getScanProtocols(opts, cfg)
	isOutputCSV := getIsOutputCSV(opts, cfg)
	isOutputTXT := getIsOutputTXT(opts, cfg)
	outputErrorLog := getOutputErrorLog(opts, cfg)
	threadTotal := getThreadTotal(opts, cfg)

	// 读取数据文件
	ipData, hostData := loadDataFiles(opts, cfg)

	// 数据校验
	if len(scanProtocols) == 0 {
		fmt.Println("\n扫描协议空, 退出程序 :(")
		os.Exit(0)
	}
	if len(strings.TrimSpace(ipData)) == 0 {
		fmt.Println("\nerror: ip数据来源, 获取为空数据, 退出程序 :(")
		os.Exit(0)
	}
	if len(strings.TrimSpace(hostData)) == 0 {
		fmt.Println("\nerror: host数据来源, 获取为空数据, 退出程序 :(")
		os.Exit(0)
	}

	// 解析 IP 和 Host 列表
	ipList := helpers.DataCleaning(helpers.ConvertStringToList(strings.TrimSpace(ipData), "\n"))
	hostList := helpers.DataCleaning(helpers.ConvertStringToList(strings.TrimSpace(hostData), "\n"))

	// ===== 初始化速率限制器 =====
	httpclient.InitRateLimiter(cfg.AntiDetection.RateLimit)

	// ===== 初始化代理池 =====
	if cfg.HTTP.ProxyPool.IsStart {
		resourcePath := config.GetResourcePath()
		proxyFilePath := helpers.FormatPath(cfg.HTTP.ProxyPool.FilePath, resourcePath)
		proxies, err := config.LoadProxyPool(proxyFilePath)
		if err != nil {
			fmt.Printf("\nerror: 加载代理池文件失败: %v\n", err)
			os.Exit(0)
		}
		if len(proxies) == 0 {
			fmt.Println("\nwarning: 代理池文件为空, 将不使用代理池")
			cfg.HTTP.ProxyPool.IsStart = false
		} else {
			pm := httpclient.GetProxyPoolManager()
			pm.Load(proxies)
			fmt.Printf("代理池已加载, 共 %d 个代理\n", len(proxies))
		}
	}

	// 输出防检测配置信息
	printAntiDetectionInfo(cfg)

	// 创建输出文件
	var csvWriter *csv.Writer
	var csvFile *os.File
	var txtFile *os.File

	outputPath := helpers.GetResultOutputFilePath()

	if isOutputCSV {
		var err error
		csvFile, err = os.Create(outputPath + ".csv")
		if err != nil {
			fmt.Printf("\nerror: csv文件创建失败: %v\n", err)
			os.Exit(0)
		}
		// 写入 BOM（支持 Excel 中文显示）
		csvFile.Write([]byte{0xEF, 0xBB, 0xBF})
		csvWriter = csv.NewWriter(csvFile)
		if err := csvWriter.Write(collision.CSVHeaders()); err != nil {
			fmt.Printf("\nerror: csv文件写入表头出错: %v\n", err)
			os.Exit(0)
		}
		csvWriter.Flush()
	}

	if isOutputTXT {
		var err error
		txtFile, err = os.Create(outputPath + ".txt")
		if err != nil {
			fmt.Printf("\nerror: txt文件创建失败: %v\n", err)
			os.Exit(0)
		}
	}

	// 优雅退出处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if csvWriter != nil {
			csvWriter.Flush()
			csvFile.Close()
		}
		if txtFile != nil {
			txtFile.Close()
		}
		fmt.Println("\n程序安全退出 :)")
		os.Exit(0)
	}()

	// 请求计数器
	var numOfRequest int64

	// 碰撞成功结果列表
	var results []*collision.CollisionResult
	var resultsMu sync.Mutex

	// IP 预检测：快速过滤不可达的IP，避免后续大量无效请求
	fmt.Println("=======================IP 预 检 测=======================")
	fmt.Printf("开始检测 %d 个IP的可达性...\n", len(ipList))
	ipList = collision.PreCheckIPs(ipList, scanProtocols, outputErrorLog)
	if len(ipList) == 0 {
		fmt.Println("\n所有IP均不可达, 退出程序 :(")
		os.Exit(0)
	}
	fmt.Printf("预检测完成, %d 个IP可达\n", len(ipList))

	// 控制台进度条（使用预检测后的IP数量计算）
	requestTotal := int64(len(ipList) * len(scanProtocols) * len(hostList))
	consoleProgressBar := progress.NewConsoleProgressBar(0, requestTotal)

	// 创建全局任务队列（替代IP分块，实现更均衡的负载分配）
	taskQueue := collision.NewTaskQueue(ipList, scanProtocols)

	// 建立 goroutine 池（所有Worker从同一个队列竞争消费任务）
	fmt.Println("=======================建 立 线 程 池=======================")
	var wg sync.WaitGroup
	for i := 0; i < threadTotal; i++ {
		fmt.Printf("协程 %d 开始运行\n", i+1)
		wg.Add(1)
		worker := collision.NewWorker(
			cfg,
			&numOfRequest,
			&results,
			&resultsMu,
			scanProtocols,
			nil, // 不再分配IP列表，从队列消费
			hostList,
			outputErrorLog,
		)
		go func() {
			defer wg.Done()
			worker.RunFromQueue(taskQueue)
		}()
	}

	fmt.Println("=======================开 始 碰 撞=======================")

	// 监控任务进度
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// 文件写入下标
	csvIndex := 0
	txtIndex := 0
	var oldNumOfRequest int64

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentNum := atomic.LoadInt64(&numOfRequest)

			// 显示当前进度
			if currentNum != oldNumOfRequest {
				oldNumOfRequest = currentNum
				consoleProgressBar.Show(currentNum)
				fmt.Println()
			}

			// CSV 数据保存
			if isOutputCSV && csvWriter != nil {
				resultsMu.Lock()
				for i := csvIndex; i < len(results); i++ {
					csvIndex++
					if err := csvWriter.Write(results[i].ToCSVRecord()); err != nil {
						fmt.Printf("\nerror: csv文件写入内容出错: %v\n", err)
						resultsMu.Unlock()
						return
					}
				}
				csvWriter.Flush()
				resultsMu.Unlock()
			}

			// TXT 数据保存
			if isOutputTXT && txtFile != nil {
				resultsMu.Lock()
				for i := txtIndex; i < len(results); i++ {
					txtIndex++
					data := results[i].ToTXTRecord() + "\r\n"
					if _, err := txtFile.WriteString(data); err != nil {
						fmt.Printf("\nerror: txt文件写入内容出错: %v\n", err)
						resultsMu.Unlock()
						return
					}
				}
				resultsMu.Unlock()
			}

		case <-done:
			// 最后一次数据写入
			if isOutputCSV && csvWriter != nil {
				resultsMu.Lock()
				for i := csvIndex; i < len(results); i++ {
					csvWriter.Write(results[i].ToCSVRecord())
				}
				csvWriter.Flush()
				csvFile.Close()
				resultsMu.Unlock()
			}
			if isOutputTXT && txtFile != nil {
				resultsMu.Lock()
				for i := txtIndex; i < len(results); i++ {
					txtFile.WriteString(results[i].ToTXTRecord() + "\r\n")
				}
				txtFile.Close()
				resultsMu.Unlock()
			}

			// 输出最终结果
			fmt.Print("\n\n\n\n\n")
			fmt.Println("====================碰 撞 成 功 列 表====================")
			if len(results) > 0 {
				for _, r := range results {
					fmt.Println(r.SuccessLog())
				}
			} else {
				fmt.Println("没有碰撞成功的数据")
			}
			fmt.Println("执行完毕 ヾ(≧▽≦*)o")
			fmt.Println()
			return
		}
	}
}

// ======== 命令行参数相关 ========

type cliOptions struct {
	help                       bool
	scanProtocol               string
	ipFilePath                 string
	hostFilePath               string
	threadTotal                int
	output                     string
	isOutputErrorLog           string
	collisionSuccessStatusCode string
	dataSampleNumber           int
	// 防检测相关
	rateLimit     int
	delayMin      int
	delayMax      int
	proxyPoolFile string
	randomUA      string
}

func parseFlags() *cliOptions {
	opts := &cliOptions{}

	flag.BoolVar(&opts.help, "h", false, "帮助")
	flag.StringVar(&opts.scanProtocol, "sp", "", "允许的扫描协议,使用逗号分割<例如:http,https>")
	flag.StringVar(&opts.ipFilePath, "ifp", "", "ip数据来源地址<例如:./dataSource/ipList.txt>")
	flag.StringVar(&opts.hostFilePath, "hfp", "", "host数据来源地址<例如:./dataSource/hostList.txt>")
	flag.IntVar(&opts.threadTotal, "t", 0, "程序运行的最大线程总数<例如:6>")
	flag.StringVar(&opts.output, "o", "", "导出格式,使用逗号分割<例如:csv,txt>")
	flag.StringVar(&opts.isOutputErrorLog, "ioel", "", "是否将错误日志输出<例如:true 输出/false 关闭>")
	flag.StringVar(&opts.collisionSuccessStatusCode, "cssc", "", "认为碰撞成功的状态码,使用逗号分割<例如: 200,301,302>")
	flag.IntVar(&opts.dataSampleNumber, "dsn", -1, "数据样本请求次数,小于等于0,表示关闭该功能")
	// 防检测相关参数
	flag.IntVar(&opts.rateLimit, "rate", -1, "速率控制,每秒最大请求数,0表示不限制<例如:50>")
	flag.IntVar(&opts.delayMin, "dmin", -1, "延迟扫描最小间隔(毫秒)<例如:1000>")
	flag.IntVar(&opts.delayMax, "dmax", -1, "延迟扫描最大间隔(毫秒)<例如:3000>")
	flag.StringVar(&opts.proxyPoolFile, "ppf", "", "代理池文件路径<例如:./dataSource/proxyList.txt>")
	flag.StringVar(&opts.randomUA, "rua", "", "是否启用UA随机化<例如:true 启用/false 关闭>")

	flag.Usage = func() {
		fmt.Println("=======================使 用 文 档=======================")
		fmt.Println("-h                                  使用文档")
		fmt.Println("-sp                                 允许的扫描协议<例如:http,https>")
		fmt.Println("-ifp                                ip数据来源地址<例如:./dataSource/ipList.txt>")
		fmt.Println("-hfp                                host数据来源地址<例如:./dataSource/hostList.txt>")
		fmt.Println("-t                                  程序运行的最大线程总数<例如:6>")
		fmt.Println("-o                                  导出格式,使用逗号分割<例如:csv,txt>")
		fmt.Println("-ioel                               是否将错误日志输出<例如:true 输出/false 关闭>")
		fmt.Println("-cssc                               认为碰撞成功的状态码,使用逗号分割<例如: 200,301,302>")
		fmt.Println("-dsn                                数据样本请求次数,小于等于0,表示关闭该功能")
		fmt.Println("")
		fmt.Println("=====================防 检 测 参 数=====================")
		fmt.Println("-rate                               速率控制,每秒最大请求数,0表示不限制<例如:50>")
		fmt.Println("-dmin                               延迟扫描最小间隔(毫秒)<例如:1000>")
		fmt.Println("-dmax                               延迟扫描最大间隔(毫秒)<例如:3000>")
		fmt.Println("-ppf                                代理池文件路径<例如:./dataSource/proxyList.txt>")
		fmt.Println("-rua                                是否启用UA随机化<例如:true 启用/false 关闭>")
	}

	flag.Parse()
	return opts
}

// ======== 配置读取（命令行 > 配置文件）========

func getScanProtocols(opts *cliOptions, cfg *config.Config) []string {
	var protocols []string
	if opts.scanProtocol != "" {
		parts := strings.Split(strings.TrimSpace(strings.ToLower(opts.scanProtocol)), ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "http" {
				protocols = append(protocols, "http://")
			}
			if p == "https" {
				protocols = append(protocols, "https://")
			}
		}
	} else {
		if cfg.HTTP.ScanProtocol.IsScanHTTP {
			protocols = append(protocols, "http://")
		}
		if cfg.HTTP.ScanProtocol.IsScanHTTPS {
			protocols = append(protocols, "https://")
		}
	}
	return protocols
}

func getIsOutputCSV(opts *cliOptions, cfg *config.Config) bool {
	if opts.output != "" {
		parts := strings.Split(strings.TrimSpace(strings.ToLower(opts.output)), ",")
		for _, p := range parts {
			if strings.TrimSpace(p) == "csv" {
				return true
			}
		}
		return false
	}
	return cfg.DefaultResultOutput.IsOutputCSV
}

func getIsOutputTXT(opts *cliOptions, cfg *config.Config) bool {
	if opts.output != "" {
		parts := strings.Split(strings.TrimSpace(strings.ToLower(opts.output)), ",")
		for _, p := range parts {
			if strings.TrimSpace(p) == "txt" {
				return true
			}
		}
		return false
	}
	return cfg.DefaultResultOutput.IsOutputTXT
}

func getOutputErrorLog(opts *cliOptions, cfg *config.Config) bool {
	if opts.isOutputErrorLog != "" {
		return strings.TrimSpace(strings.ToLower(opts.isOutputErrorLog)) != "false"
	}
	return cfg.IsOutputErrorLog
}

func getThreadTotal(opts *cliOptions, cfg *config.Config) int {
	t := cfg.ThreadTotal
	if opts.threadTotal > 0 {
		t = opts.threadTotal
	}
	if t <= 0 {
		t = 1
	}
	return t
}

func loadDataFiles(opts *cliOptions, cfg *config.Config) (string, string) {
	resourcePath := config.GetResourcePath()

	// IP 文件路径
	ipPath := helpers.FormatPath(cfg.DataSource.IPFilePath, resourcePath)
	if opts.ipFilePath != "" {
		ipPath = helpers.FormatPath(opts.ipFilePath, resourcePath)
	}

	// Host 文件路径
	hostPath := helpers.FormatPath(cfg.DataSource.HostFilePath, resourcePath)
	if opts.hostFilePath != "" {
		hostPath = helpers.FormatPath(opts.hostFilePath, resourcePath)
	}

	ipData, err := helpers.GetFileData(ipPath)
	if err != nil {
		fmt.Printf("\nerror: 文件读/写出错, IP文件路径: %s\n%v\n", ipPath, err)
		os.Exit(0)
	}

	hostData, err := helpers.GetFileData(hostPath)
	if err != nil {
		fmt.Printf("\nerror: 文件读/写出错, Host文件路径: %s\n%v\n", hostPath, err)
		os.Exit(0)
	}

	return ipData, hostData
}

func basicInformationOutput() string {
	str1 := "=======================基 本 信 息=======================\n"
	str3 := fmt.Sprintf("原始项目: %s\n", "https://github.com/AbnerEarl/HostCollision")
	str4 := "请尽情享用本程序吧 ヾ(≧▽≦*)o"
	return str1 + str3 + str4
}

// printAntiDetectionInfo 输出防检测配置信息
func printAntiDetectionInfo(cfg *config.Config) {
	fmt.Println("=======================防 检 测 配 置=======================")

	// UA 随机化
	if cfg.AntiDetection.RandomUA {
		fmt.Println("[✓] User-Agent 随机化: 已启用")
	} else {
		fmt.Println("[✗] User-Agent 随机化: 已关闭")
	}

	// Header 伪造
	if cfg.AntiDetection.FakeHeaders.IsStart && len(cfg.AntiDetection.FakeHeaders.Headers) > 0 {
		headers := make([]string, 0, len(cfg.AntiDetection.FakeHeaders.Headers))
		for k := range cfg.AntiDetection.FakeHeaders.Headers {
			headers = append(headers, k)
		}
		fmt.Printf("[✓] Header 伪造(Bypass WAF): 已启用, 伪造头: %s\n", strings.Join(headers, ", "))
	} else {
		fmt.Println("[✗] Header 伪造(Bypass WAF): 已关闭")
	}

	// 速率控制
	if cfg.AntiDetection.RateLimit > 0 {
		fmt.Printf("[✓] 速率控制: 已启用, 最大 %d 请求/秒\n", cfg.AntiDetection.RateLimit)
	} else {
		fmt.Println("[✗] 速率控制: 已关闭(不限速)")
	}

	// 延迟扫描
	if cfg.AntiDetection.Delay.IsStart {
		fmt.Printf("[✓] 延迟扫描: 已启用, 间隔 %d~%d 毫秒\n",
			cfg.AntiDetection.Delay.MinMs, cfg.AntiDetection.Delay.MaxMs)
	} else {
		fmt.Println("[✗] 延迟扫描: 已关闭")
	}

	// 代理池
	if cfg.HTTP.ProxyPool.IsStart {
		pm := httpclient.GetProxyPoolManager()
		fmt.Printf("[✓] 代理池(IP轮换): 已启用, 共 %d 个代理\n", pm.Size())
	} else if cfg.HTTP.Proxy.IsStart {
		fmt.Printf("[✓] 单一代理: 已启用, %s:%d\n", cfg.HTTP.Proxy.Host, cfg.HTTP.Proxy.Port)
	} else {
		fmt.Println("[✗] 代理: 已关闭(直连)")
	}
	fmt.Println()
}
