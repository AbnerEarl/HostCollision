package httpclient

import (
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// TestDetectAndConvertToUTF8_GBK 测试 GBK 编码的内容能被正确转换为 UTF-8
func TestDetectAndConvertToUTF8_GBK(t *testing.T) {
	tests := []struct {
		name        string
		utf8Content string // 原始 UTF-8 内容
		contentType string // Content-Type header
		wantCJK     bool   // 期望结果中包含 CJK 字符
	}{
		{
			name:        "GBK页面无charset声明",
			utf8Content: "<html><head><title>搜狐畅游</title></head><body>携程旅行网</body></html>",
			contentType: "text/html",
			wantCJK:     true,
		},
		{
			name:        "GBK页面有meta charset声明",
			utf8Content: `<html><head><meta charset="gbk"><title>搜狐畅游</title></head><body>携程旅行网</body></html>`,
			contentType: "text/html",
			wantCJK:     true,
		},
		{
			name:        "GBK页面Content-Type声明charset",
			utf8Content: "<html><head><title>搜狐畅游</title></head><body>携程旅行网</body></html>",
			contentType: "text/html; charset=gbk",
			wantCJK:     true,
		},
		{
			name:        "纯UTF-8页面",
			utf8Content: "<html><head><title>Hello World</title></head><body>Test</body></html>",
			contentType: "text/html; charset=utf-8",
			wantCJK:     false,
		},
		{
			name:        "UTF-8中文页面",
			utf8Content: "<html><head><title>你好世界</title></head><body>测试内容</body></html>",
			contentType: "text/html; charset=utf-8",
			wantCJK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 将 UTF-8 内容编码为 GBK（模拟 GBK 编码的服务器响应）
			var body []byte
			if tt.contentType == "text/html; charset=utf-8" {
				// UTF-8 页面直接使用 UTF-8 字节
				body = []byte(tt.utf8Content)
			} else {
				// 非 UTF-8 页面，先转换为 GBK 字节
				gbkEncoder := simplifiedchinese.GBK.NewEncoder()
				gbkBytes, err := gbkEncoder.Bytes([]byte(tt.utf8Content))
				if err != nil {
					t.Fatalf("GBK 编码失败: %v", err)
				}
				body = gbkBytes
			}

			result := detectAndConvertToUTF8(body, tt.contentType)

			// 检查结果中是否包含 CJK 字符
			cjkCount := countCJKChars(result)
			if tt.wantCJK && cjkCount == 0 {
				t.Errorf("期望结果包含 CJK 字符，但未找到。结果: %s", result)
			}

			// 检查是否包含典型乱码字符
			for _, ch := range result {
				if ch == '鎼' || ch == '鏃' || ch == '缃' {
					t.Errorf("检测到乱码字符 '%c'，编码转换可能失败。结果: %s", ch, result)
					break
				}
			}

			t.Logf("输入ContentType: %s, 输出: %s (CJK字符数: %d)", tt.contentType, result, cjkCount)
		})
	}
}

// TestDetectAndConvertToUTF8_EmptyBody 测试空内容
func TestDetectAndConvertToUTF8_EmptyBody(t *testing.T) {
	result := detectAndConvertToUTF8(nil, "text/html")
	if result != "" {
		t.Errorf("空内容应返回空字符串，实际: %s", result)
	}

	result = detectAndConvertToUTF8([]byte{}, "text/html")
	if result != "" {
		t.Errorf("空字节应返回空字符串，实际: %s", result)
	}
}

// TestTryGBKDecode 测试 GBK 解码函数
func TestTryGBKDecode(t *testing.T) {
	// 将 "搜狐畅游" 编码为 GBK
	gbkEncoder := simplifiedchinese.GBK.NewEncoder()
	gbkBytes, err := gbkEncoder.Bytes([]byte("搜狐畅游"))
	if err != nil {
		t.Fatalf("GBK 编码失败: %v", err)
	}

	result := tryGBKDecode(gbkBytes)
	if result != "搜狐畅游" {
		t.Errorf("GBK 解码失败，期望: 搜狐畅游, 实际: %s", result)
	}

	// 测试纯 ASCII 内容
	result = tryGBKDecode([]byte("Hello World"))
	if result != "Hello World" {
		t.Errorf("ASCII 内容 GBK 解码失败，期望: Hello World, 实际: %s", result)
	}
}

// TestCountCJKChars 测试 CJK 字符计数
func TestCountCJKChars(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"Hello World", 0},
		{"你好世界", 4},
		{"Hello 你好", 2},
		{"搜狐畅游 Test 携程旅行", 8},
		{"", 0},
		{"鎼虹▼鏃呰缃", 5}, // 乱码中也可能包含 CJK 范围的字符
	}

	for _, tt := range tests {
		got := countCJKChars(tt.input)
		if got != tt.want {
			t.Errorf("countCJKChars(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
