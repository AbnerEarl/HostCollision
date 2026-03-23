package progress

import (
	"fmt"
	"strings"
	"sync"
)

// ConsoleProgressBar 控制台字符型进度条
type ConsoleProgressBar struct {
	mu       sync.Mutex
	minimum  int64 // 进度条-起始值
	maximum  int64 // 进度条-最大值
	length   int64 // 进度条-长度
	showChar rune  // 用于进度条显示的字符
}

// NewConsoleProgressBar 创建进度条
func NewConsoleProgressBar(minimum, maximum int64) *ConsoleProgressBar {
	return &ConsoleProgressBar{
		minimum:  minimum,
		maximum:  maximum,
		length:   50,
		showChar: '█',
	}
}

// Show 显示进度条
func (p *ConsoleProgressBar) Show(value int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if value < 0 || value > p.maximum {
		return
	}
	p.minimum = value
	p.reset()
	rate := float64(p.minimum) / float64(p.maximum)
	barLen := int64(rate * float64(p.length))
	p.draw(barLen, rate)
	if p.minimum == p.maximum {
		p.afterComplete()
	}
}

func (p *ConsoleProgressBar) reset() {
	fmt.Printf("\r当前进度 %d/%d: [", p.minimum, p.maximum)
}

func (p *ConsoleProgressBar) draw(barLen int64, rate float64) {
	bar := strings.Repeat(string(p.showChar), int(barLen))
	fmt.Printf("%s] %.2f%%", bar, rate*100)
}

func (p *ConsoleProgressBar) afterComplete() {
	fmt.Println()
}
