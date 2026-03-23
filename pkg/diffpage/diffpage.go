package diffpage

import (
	"math"
	"regexp"
	"strings"
)

// GetRatio 返回经过过滤无用数据后两个字符串的相似度
func GetRatio(str, target string) float64 {
	str = GetFilteredPageContent(str)
	target = GetFilteredPageContent(target)
	return GetSimilarityRatio(str, target)
}

// GetFilteredPageContent 返回经过过滤的页面内容，去除脚本、样式、注释和HTML标签
// 例如: getFilteredPageContent("<html><title>foobar</title></style><body>test</body></html>")
// 返回: foobartest
func GetFilteredPageContent(htmlStr string) string {
	// 将实体字符串转义
	htmlStr = strings.ReplaceAll(htmlStr, "&lt;", "<")
	htmlStr = strings.ReplaceAll(htmlStr, "&gt;", ">")
	htmlStr = strings.ReplaceAll(htmlStr, "&quot;", "\"")
	htmlStr = strings.ReplaceAll(htmlStr, "&nbsp;", " ")
	htmlStr = strings.ReplaceAll(htmlStr, "&amp;", "&")

	// 去除 script 标签
	scriptRegex := regexp.MustCompile(`(?is)<script[^>]*?>[\s\S]*?</script>`)
	htmlStr = scriptRegex.ReplaceAllString(htmlStr, "")

	// 去除 style 标签
	styleRegex := regexp.MustCompile(`(?is)<style[^>]*?>[\s\S]*?</style>`)
	htmlStr = styleRegex.ReplaceAllString(htmlStr, "")

	// 去除 HTML 标签
	htmlRegex := regexp.MustCompile(`<[^>]+>`)
	htmlStr = htmlRegex.ReplaceAllString(htmlStr, "")

	// 去除特殊字符 如: &nbsp;
	specialRegex1 := regexp.MustCompile(`&[a-zA-Z]{1,10};`)
	htmlStr = specialRegex1.ReplaceAllString(htmlStr, "")

	// 去除特殊字符 如: &#xe625;
	specialRegex2 := regexp.MustCompile(`&#[a-zA-Z0-9]{1,10};`)
	htmlStr = specialRegex2.ReplaceAllString(htmlStr, "")

	// 过滤空格、回车、换行、制表符
	spaceRegex := regexp.MustCompile(`[\s\t\r\n]+`)
	htmlStr = spaceRegex.ReplaceAllString(htmlStr, "")

	return strings.TrimSpace(htmlStr)
}

// GetSimilarityRatio 两个字符串相似度匹配（基于编辑距离/Levenshtein距离）
func GetSimilarityRatio(str, target string) float64 {
	if str == target {
		return 1
	}

	n := len([]rune(str))
	m := len([]rune(target))

	if n == 0 || m == 0 {
		return 0
	}

	strRunes := []rune(str)
	targetRunes := []rune(target)

	// 创建矩阵
	d := make([][]int, n+1)
	for i := range d {
		d[i] = make([]int, m+1)
	}

	// 初始化第一列
	for i := 0; i <= n; i++ {
		d[i][0] = i
	}

	// 初始化第一行
	for j := 0; j <= m; j++ {
		d[0][j] = j
	}

	// 遍历计算
	for i := 1; i <= n; i++ {
		ch1 := strRunes[i-1]
		for j := 1; j <= m; j++ {
			ch2 := targetRunes[j-1]
			temp := 1
			// 忽略大小写比较
			if ch1 == ch2 || ch1 == ch2+32 || ch1+32 == ch2 {
				temp = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+temp)
		}
	}

	return 1 - float64(d[n][m])/math.Max(float64(n), float64(m))
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
