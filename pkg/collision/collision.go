package collision

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AbnerEarl/HostCollision/pkg/config"
	"github.com/AbnerEarl/HostCollision/pkg/diffpage"
	"github.com/AbnerEarl/HostCollision/pkg/httpclient"
)

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
	return &Worker{
		cfg:            cfg,
		numOfRequest:   numOfRequest,
		results:        results,
		resultsMu:      resultsMu,
		scanProtocols:  scanProtocols,
		ipList:         ipList,
		hostList:       hostList,
		outputErrorLog: outputErrorLog,
	}
}

// Run 执行碰撞任务
func (w *Worker) Run() {
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

	// 基础请求
	baseRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, "")
	if err != nil {
		atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
		if w.outputErrorLog {
			fmt.Printf("error: 站点 %s 访问失败,不进行host碰撞\n", protocol+ip)
		}
		return
	}

	// 绝对错误请求
	errorHostRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, w.cfg.HTTP.ErrorHost)
	if err != nil {
		atomic.AddInt64(w.numOfRequest, int64(len(w.hostList)))
		if w.outputErrorLog {
			fmt.Printf("error: 站点 %s 访问失败,不进行host碰撞\n", protocol+ip)
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

	for _, host := range w.hostList {
		atomic.AddInt64(w.numOfRequest, 1)
		w.collision(&dataSample, baseRequest, errorHostRequest, protocol, ip, host)
	}
}

// collision Host碰撞核心逻辑
func (w *Worker) collision(
	dataSample *[]*httpclient.HttpCustomRequest,
	baseRequest, errorHostRequest *httpclient.HttpCustomRequest,
	protocol, ip, host string,
) {
	// 碰撞请求
	newRequest, err := httpclient.SendHTTPGetRequest(protocol, ip, host)
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-1\n", protocol, ip, host)
		}
		return
	}

	// 相对错误请求
	newRequest2, err := httpclient.SendHTTPGetRequest(protocol, ip, w.cfg.HTTP.RelativeHostName+host)
	if err != nil {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-1\n", protocol, ip, host)
		}
		return
	}

	// 请求之间的长度判断
	if ok, req := requestLengthMatching([]*httpclient.HttpCustomRequest{newRequest, newRequest2}); !ok {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 该请求长度为%d 有异常,不进行碰撞-2\n",
				protocol, ip, req.Host, req.ContentLen)
		}
		return
	}

	// 请求之间的内容匹配
	if !requestContentMatching(baseRequest, errorHostRequest, newRequest, newRequest2) {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-2\n", protocol, ip, host)
		}
		return
	}

	// 请求之间的 title 匹配
	if !requestTitleMatching(baseRequest, errorHostRequest, newRequest, newRequest2) {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-3\n", protocol, ip, host)
		}
		return
	}

	// 相似度匹配
	ratio1 := diffpage.GetRatio(baseRequest.BodyFormat(), newRequest.BodyFormat())
	ratio2 := diffpage.GetRatio(errorHostRequest.BodyFormat(), newRequest.BodyFormat())
	ratio3 := diffpage.GetRatio(newRequest2.BodyFormat(), newRequest.BodyFormat())
	if ratio1 >= w.cfg.SimilarityRatio || ratio2 >= w.cfg.SimilarityRatio || ratio3 >= w.cfg.SimilarityRatio {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s 匹配失败-4\n", protocol, ip, host)
		}
		return
	}

	// 数据样本生成
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
			return
		}
	}

	// HTTP 状态码检查
	statusCodes := getCollisionSuccessStatusCodes(w.cfg.CollisionSuccessStatusCode)
	if !httpStatusCodeCheck(fmt.Sprintf("%d", newRequest.StatusCode), statusCodes) {
		if w.outputErrorLog {
			fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 不是白名单状态码,忽略处理\n",
				protocol, ip, host, newRequest.Title(), newRequest.ContentLen, newRequest.StatusCode)
		}
		return
	}

	// WAF 检查
	if w.cfg.DataSample.Number > 0 && len(*dataSample) > 0 {
		if ok, wafReq := wafFeatureMatching(w.cfg, baseRequest, newRequest); !ok {
			if w.outputErrorLog {
				fmt.Printf("协议:%s, ip:%s, host:%s, title:%s, 数据包大小:%d, 状态码:%d 匹配到waf特征,忽略处理\n",
					protocol, ip, wafReq.Host, wafReq.Title(), wafReq.ContentLen, wafReq.StatusCode)
			}
			return
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
}

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

// requestContentMatching 请求之间的内容匹配
// 用途: 初步的误报检测
// 返回: true 表示通过
func requestContentMatching(baseReq, errorHostReq, newReq, newReq2 *httpclient.HttpCustomRequest) bool {
	newBody := newReq.AppBody()
	baseBody := baseReq.AppBody()
	errorBody := errorHostReq.AppBody()
	relativeBody := newReq2.AppBody()

	if len(newBody) > 0 {
		if strings.Contains(newBody, baseBody) || strings.Contains(baseBody, newBody) {
			return false
		}
	}

	if len(errorBody) > 0 {
		if strings.Contains(newBody, errorBody) || strings.Contains(errorBody, newBody) {
			return false
		}
	}

	if len(relativeBody) > 0 {
		if strings.Contains(newBody, relativeBody) || strings.Contains(relativeBody, newBody) {
			return false
		}
	}

	return true
}

// requestTitleMatching 请求之间的 title 匹配
// 用途: 初步的误报检测
// 返回: true 表示通过
func requestTitleMatching(baseReq, errorHostReq, newReq, newReq2 *httpclient.HttpCustomRequest) bool {
	newTitle := strings.TrimSpace(newReq.Title())
	if len(newTitle) > 0 {
		if newReq2.Title() == newTitle {
			return false
		}
		if baseReq.Title() == newTitle {
			return false
		}
		if errorHostReq.Title() == newTitle {
			return false
		}
	}
	return true
}

// sampleSimilarityCheck 样本相似度检查
// 用于判断当前字符串与样本数组是否有相似的数据出现
// true 表示有相似数据出现, false 表示没有相似数据出现
func sampleSimilarityCheck(str string, samples []*httpclient.HttpCustomRequest, ratio float64) bool {
	for _, r := range samples {
		sim := diffpage.GetRatio(r.BodyFormat(), str)
		if sim >= ratio {
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

// getCollisionSuccessStatusCodes 解析碰撞成功状态码配置
func getCollisionSuccessStatusCodes(statusCodeStr string) []string {
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

// wafFeatureMatching WAF 特征匹配
// 返回: true 表示通过(无 WAF), false 表示匹配到 WAF
func wafFeatureMatching(cfg *config.Config, baseReq, newReq *httpclient.HttpCustomRequest) (bool, *httpclient.HttpCustomRequest) {
	if httpHeaderServiceWafMatching(cfg, baseReq, newReq) {
		return false, newReq
	}
	if httpBodyWafMatching(cfg, baseReq, newReq) {
		return false, newReq
	}
	if httpHeaderXPoweredByWafMatching(cfg, baseReq, newReq) {
		return false, newReq
	}
	return true, nil
}

// httpHeaderServiceWafMatching HTTP 请求 header Server 字段的 WAF 特征匹配
// true 表示匹配到 WAF 特征
func httpHeaderServiceWafMatching(cfg *config.Config, baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bs := baseReq.ServerHeader
	s := newReq.ServerHeader

	if bs != "" && s != "" {
		if bs == s {
			return false
		}
	}

	if s != "" {
		blacklists := cfg.GetHTTPServiceBlacklists()
		if len(blacklists) > 0 {
			sLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
			for _, bl := range blacklists {
				bl = strings.ReplaceAll(bl, " ", "")
				if strings.Contains(sLower, bl) {
					return true
				}
			}
		}
	}
	return false
}

// httpBodyWafMatching HTTP 请求 body 的 WAF 特征匹配
// true 表示匹配到 WAF 特征
func httpBodyWafMatching(cfg *config.Config, baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bab := baseReq.AppBody()
	ab := newReq.AppBody()

	if bab != "" && ab != "" {
		if bab == ab {
			return false
		}
	}

	if ab != "" {
		blacklists := cfg.GetHTTPBodyBlacklists()
		if len(blacklists) > 0 {
			abLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(ab, " ", "")))
			for _, bl := range blacklists {
				bl = strings.ReplaceAll(bl, " ", "")
				if strings.Contains(abLower, bl) {
					return true
				}
			}
		}
	}
	return false
}

// httpHeaderXPoweredByWafMatching HTTP 请求 header X-Powered-By 字段的 WAF 特征匹配
// true 表示匹配到 WAF 特征
func httpHeaderXPoweredByWafMatching(cfg *config.Config, baseReq, newReq *httpclient.HttpCustomRequest) bool {
	bxp := baseReq.XPoweredByVal
	xp := newReq.XPoweredByVal

	if bxp != "" && xp != "" {
		if bxp == xp {
			return false
		}
	}

	if xp != "" {
		blacklists := cfg.GetHTTPXPoweredByBlacklists()
		if len(blacklists) > 0 {
			xpLower := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(xp, " ", "")))
			for _, bl := range blacklists {
				bl = strings.ReplaceAll(bl, " ", "")
				if strings.Contains(xpLower, bl) {
					return true
				}
			}
		}
	}
	return false
}
