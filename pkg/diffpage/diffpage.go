package diffpage

import (
	"math"
	"regexp"
	"strings"
)

// ========== 预编译正则表达式（避免每次调用都重新编译）==========

var (
	scriptRegex  = regexp.MustCompile(`(?is)<script[^>]*?>[\s\S]*?</script>`)
	styleRegex   = regexp.MustCompile(`(?is)<style[^>]*?>[\s\S]*?</style>`)
	htmlRegex    = regexp.MustCompile(`<[^>]+>`)
	specialRegex = regexp.MustCompile(`&[a-zA-Z]{1,10};`)
	unicodeRegex = regexp.MustCompile(`&#[a-zA-Z0-9]{1,10};`)
	spaceRegex   = regexp.MustCompile(`[\s\t\r\n]+`)
)

// GetRatio 返回经过过滤无用数据后两个字符串的相似度
func GetRatio(str, target string) float64 {
	str = GetFilteredPageContent(str)
	target = GetFilteredPageContent(target)
	return GetSimilarityRatio(str, target)
}

// GetRatioWithThreshold 带阈值的相似度计算，当确定相似度不可能达到阈值时提前终止
// 返回值: 相似度, 是否达到阈值
func GetRatioWithThreshold(str, target string, threshold float64) (float64, bool) {
	str = GetFilteredPageContent(str)
	target = GetFilteredPageContent(target)
	ratio := getSimilarityRatioWithThreshold(str, target, threshold)
	return ratio, ratio >= threshold
}

// GetFilteredPageContent 返回经过过滤的页面内容，去除脚本、样式、注释和HTML标签
// 例如: getFilteredPageContent("<html><title>foobar</title></style><body>test</body></html>")
// 返回: foobartest
func GetFilteredPageContent(htmlStr string) string {
	if len(htmlStr) == 0 {
		return ""
	}

	// 将实体字符串转义
	htmlStr = strings.ReplaceAll(htmlStr, "&lt;", "<")
	htmlStr = strings.ReplaceAll(htmlStr, "&gt;", ">")
	htmlStr = strings.ReplaceAll(htmlStr, "&quot;", "\"")
	htmlStr = strings.ReplaceAll(htmlStr, "&nbsp;", " ")
	htmlStr = strings.ReplaceAll(htmlStr, "&amp;", "&")

	// 使用预编译的正则表达式
	htmlStr = scriptRegex.ReplaceAllString(htmlStr, "")
	htmlStr = styleRegex.ReplaceAllString(htmlStr, "")
	htmlStr = htmlRegex.ReplaceAllString(htmlStr, "")
	htmlStr = specialRegex.ReplaceAllString(htmlStr, "")
	htmlStr = unicodeRegex.ReplaceAllString(htmlStr, "")
	htmlStr = spaceRegex.ReplaceAllString(htmlStr, "")

	return strings.TrimSpace(htmlStr)
}

// GetSimilarityRatio 两个字符串相似度匹配（基于编辑距离/Levenshtein距离）
// 使用两行滚动数组优化，空间复杂度从 O(n*m) 降低到 O(min(n,m))
func GetSimilarityRatio(str, target string) float64 {
	return getSimilarityRatioWithThreshold(str, target, 0)
}

// getSimilarityRatioWithThreshold 带阈值提前终止的编辑距离计算
// 使用两行滚动数组，空间复杂度 O(min(n,m))
// 当 threshold > 0 时，如果当前行的最小编辑距离已经不可能达到阈值，提前返回 0
func getSimilarityRatioWithThreshold(str, target string, threshold float64) float64 {
	if str == target {
		return 1
	}

	strRunes := []rune(str)
	targetRunes := []rune(target)
	n := len(strRunes)
	m := len(targetRunes)

	if n == 0 || m == 0 {
		return 0
	}

	// 确保 n >= m，让较短的字符串作为列（减少内存使用）
	if n < m {
		strRunes, targetRunes = targetRunes, strRunes
		n, m = m, n
	}

	maxLen := float64(n)

	// 快速长度差异检查：如果长度差异已经超过阈值允许的最大编辑距离，直接返回
	if threshold > 0 {
		lenDiff := n - m
		maxAllowedDist := int(math.Ceil((1 - threshold) * maxLen))
		if lenDiff > maxAllowedDist {
			return 0
		}
	}

	// 使用两行滚动数组代替完整矩阵
	prev := make([]int, m+1)
	curr := make([]int, m+1)

	// 初始化第一行
	for j := 0; j <= m; j++ {
		prev[j] = j
	}

	// 计算阈值对应的最大允许编辑距离
	maxAllowedDist := n + m // 默认不限制
	if threshold > 0 {
		maxAllowedDist = int(math.Ceil((1 - threshold) * maxLen))
	}

	for i := 1; i <= n; i++ {
		curr[0] = i
		ch1 := strRunes[i-1]
		rowMin := curr[0] // 跟踪当前行的最小值

		for j := 1; j <= m; j++ {
			ch2 := targetRunes[j-1]
			cost := 1
			// 忽略大小写比较
			if ch1 == ch2 || ch1 == ch2+32 || ch1+32 == ch2 {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
			if curr[j] < rowMin {
				rowMin = curr[j]
			}
		}

		// 提前终止：如果当前行最小编辑距离已经超过允许的最大值，不可能达到阈值
		if threshold > 0 && rowMin > maxAllowedDist {
			return 0
		}

		// 交换行（避免内存分配）
		prev, curr = curr, prev
	}

	return 1 - float64(prev[m])/maxLen
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
