package helpers

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RandomStr 随机生成指定长度的字符串
func RandomStr(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}

// ConvertStringToList 按分隔符将字符串转换为列表
func ConvertStringToList(str, mark string) []string {
	return strings.Split(str, mark)
}

// DataCleaning 数据清理：去除空白行和首尾空格
func DataCleaning(dataSource []string) []string {
	var result []string
	for _, d := range dataSource {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		result = append(result, d)
	}
	return result
}

// ListChunkSplit 列表块分割函数
// 功能: 把列表按照 groupSize 分割成指定数量的子列表
// 例子: a = [1,2,3,4,5,6,7,8,9], listChunkSplit(a, 2) => [[1,2,3,4,5],[6,7,8,9]]
func ListChunkSplit(dataSource []string, groupSize int) [][]string {
	var result [][]string

	if len(dataSource) == 0 || groupSize == 0 {
		return result
	}

	// 如果 groupSize 大于数据源长度，则每个元素一个分组
	if groupSize > len(dataSource) {
		groupSize = len(dataSource)
	}

	offset := 0
	number := len(dataSource) / groupSize
	remainder := len(dataSource) % groupSize

	for i := 0; i < groupSize; i++ {
		var chunk []string
		if remainder > 0 {
			chunk = dataSource[i*number+offset : (i+1)*number+offset+1]
			remainder--
			offset++
		} else {
			chunk = dataSource[i*number+offset : (i+1)*number+offset]
		}

		if len(chunk) == 0 {
			break
		}
		result = append(result, chunk)
	}

	return result
}

// GetFileData 获取文件数据
func GetFileData(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetBodyTitle 获取网页标题
func GetBodyTitle(s string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindAllStringSubmatch(s, -1)
	var titles []string
	for _, match := range matches {
		if len(match) > 1 {
			titles = append(titles, match[1])
		}
	}
	return strings.Join(titles, "")
}

// GetResultOutputFilePath 获取结果输出的文件路径
func GetResultOutputFilePath() string {
	date := time.Now().Format("2006-01-02")
	return fmt.Sprintf(".%s%s_%s", string(filepath.Separator), date, RandomStr(8))
}

// FormatPath 路径格式化
func FormatPath(path string, resourcePath string) string {
	path = filepath.FromSlash(path)

	sep := string(filepath.Separator)

	if strings.HasPrefix(path, "."+sep) {
		return resourcePath + path[1:]
	} else if strings.HasPrefix(path, sep) {
		return path
	} else {
		return resourcePath + sep + path
	}
}
