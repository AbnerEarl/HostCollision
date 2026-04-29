package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
	"unicode"

	hostcollision "github.com/AbnerEarl/HostCollision"
)

// TestCase2Message 测试用例2的消息结构
type TestCase2Message struct {
	Id    uint     `json:"id"`
	Ips   []string `json:"ips"`
	Hosts []string `json:"hosts"`
}

// 使用用户提供的实际碰撞数据作为测试用例
// 验证目标：
// 1. GBK 编码的 Title 不再出现乱码（如 "鎼虹▼鏃呰缃" 应被正确解码为中文）
// 2. 直接请求 Host 结果一致的应被过滤（如 tourapi.ctrip.com 等）
// 3. SimHash 相同的跨 IP 结果应被去重（如 SimHash=1321359412556271772 的多条记录）
var testData2 = `{
	"id": 1001,
	"ips": [
		"2.16.244.25",
		"23.32.20.50",
		"23.45.207.83",
		"172.67.176.158",
		"172.67.210.169",
		"104.21.75.41",
		"104.21.36.64"
	],
	"hosts": [
		"agent.easytrip.com",
		"external.ctrip.com",
		"seoplat.trip.com",
		"tourapi.ctrip.com",
		"img-origin.c-ctrip.com",
		"noc2.ctrip.com",
		"wingon-wireless-restful.ctrip.com",
		"nephele.ctrip.com",
		"dms-admin-cf.ctrip.com",
		"ttdopen.ctrip.com",
		"kr.trip.com",
		"nephele-admin.ctrip.com",
		"sopenservice.ctrip.com",
		"m.suanya.com",
		"big5.ctrip.com",
		"diybst.ctrip.com",
		"12306.tieyou.com",
		"openapiadmin.ctripbiz.com",
		"nephele.tripcdn.com",
		"ttdstp.ctrip.com",
		"webhook-igtday.ctrip.com",
		"www.suanya.com",
		"u.ctrip.com",
		"zcm99.com",
		"wsspush.ctrip.com",
		"ru.ctrip.com",
		"jiudian.tieyou.com",
		"cjlqscb.cc.cd"
	]
}`

// isGarbledTitle 检测 Title 是否为乱码
// 使用多种策略检测常见的编码错误
func isGarbledTitle(title string) bool {
	if title == "" {
		return false
	}

	// 策略1：检查典型的编码错误特征字符
	// GBK 内容被当作 UTF-8 读取时的常见乱码字符
	garbledChars := []rune{'鎼', '鏃', '缃', '▼', '鐏', '绁', '璇', '璐', '綉', '銆', '櫤', '琛', '伀', '杞', '︾', '鑳'}
	for _, ch := range title {
		for _, gc := range garbledChars {
			if ch == gc {
				return true
			}
		}
	}

	// 策略2：检查是否包含大量罕见/不常用的 CJK 字符
	// 乱码通常包含大量 CJK 扩展区的字符，而正常中文主要使用基本区
	totalChars := 0
	rareCJKChars := 0
	replacementChars := 0
	for _, ch := range title {
		if ch == '�' || ch == '\uFFFD' {
			replacementChars++
		}
		if unicode.Is(unicode.Han, ch) {
			totalChars++
			// CJK 统一汉字扩展 B 及以上区域（U+20000+）或罕见字符
			if ch >= 0x20000 || (ch >= 0x3400 && ch <= 0x4DBF) {
				rareCJKChars++
			}
		}
	}

	// 如果有替换字符，说明有编码错误
	if replacementChars > 0 {
		return true
	}

	// 如果 CJK 字符中罕见字符占比超过 50%，可能是乱码
	if totalChars > 2 && float64(rareCJKChars)/float64(totalChars) > 0.5 {
		return true
	}

	// 策略3：检查是否包含注音符号（ㄅ-ㄩ）
	// UTF-8→GBK 误解码时常产生注音符号
	bopomofoCount := 0
	for _, ch := range title {
		if ch >= 0x3105 && ch <= 0x3129 { // 注音符号范围 ㄅ-ㄩ
			bopomofoCount++
		}
	}
	if bopomofoCount > 2 {
		return true
	}

	return false
}

func main() {
	startTime := time.Now()

	var message TestCase2Message
	if err := json.Unmarshal([]byte(testData2), &message); err != nil {
		log.Fatalf("测试数据反序列化失败: %v\n", err)
	}

	fmt.Println("========== 测试用例2: 验证乱码修复 + Host过滤 + SimHash跨IP去重 ==========")
	fmt.Printf("IP数量：%d，Host数量：%d\n", len(message.Ips), len(message.Hosts))
	fmt.Printf("预期碰撞组合数：%d\n", len(message.Ips)*len(message.Hosts))
	fmt.Println()

	results, err := hostcollision.Run(message.Ips, message.Hosts)
	if err != nil {
		log.Fatalf("碰撞失败: %v", err)
	}

	fmt.Printf("\n========== 碰撞结果: 发现 %d 个资产 ==========\n", len(results))

	// 统计分析
	titleCount := make(map[string]int)
	simhashCount := make(map[uint64]int)
	garbledCount := 0

	for _, r := range results {
		fmt.Printf("协议:%s, IP:%s, Host:%s, Title:[%s], ContentLen:%d, StatusCode:%d, SimHash:%d\n",
			r.Protocol, r.IP, r.Host, r.Title, r.MatchContentLen, r.MatchStatusCode, r.BodySimhash)

		titleCount[r.Title]++
		simhashCount[r.BodySimhash]++

		// 检测乱码：使用更通用的方法
		// 1. 检查典型的 GBK→UTF-8 误解码特征字符
		// 2. 检查 UTF-8→GBK 误解码特征字符
		// 3. 检查是否包含大量罕见 CJK 字符（乱码特征）
		if isGarbledTitle(r.Title) {
			garbledCount++
			fmt.Printf("  ⚠️ 检测到疑似乱码 Title: [%s]\n", r.Title)
		}
	}

	fmt.Println()
	fmt.Println("========== 验证报告 ==========")

	// 验证1: 乱码检测
	if garbledCount > 0 {
		fmt.Printf("❌ 乱码检测: 发现 %d 条疑似乱码 Title\n", garbledCount)
	} else {
		fmt.Println("✅ 乱码检测: 未发现乱码 Title")
	}

	// 验证2: SimHash 去重效果
	duplicateSimhash := 0
	for hash, count := range simhashCount {
		if count > 1 {
			duplicateSimhash++
			fmt.Printf("❌ SimHash 去重: SimHash=%d 出现了 %d 次\n", hash, count)
		}
	}
	if duplicateSimhash == 0 {
		fmt.Println("✅ SimHash 去重: 无重复 SimHash")
	}

	// 验证3: 重复 Title 统计
	fmt.Println()
	fmt.Println("Title 分布统计:")
	for title, count := range titleCount {
		if title == "" {
			fmt.Printf("  [空Title]: %d 条\n", count)
		} else {
			fmt.Printf("  [%s]: %d 条\n", title, count)
		}
	}

	fmt.Printf("\n总耗时：%.2f 秒\n", time.Since(startTime).Seconds())
}
