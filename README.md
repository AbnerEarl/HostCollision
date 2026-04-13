
# 🎯 HostCollision — 高性能 Host 碰撞工具 (Go Edition)

> 通过 IP 列表 + 域名列表进行快速 Host 碰撞，发现隐藏在 CDN / 反向代理 / 负载均衡 背后的真实资产。
> 
> **既是命令行工具，也是 Go 依赖库** —— 一行 `go get` 即可集成到你的项目中。

```
 _   _           _    ____      _ _ _     _
| | | | ___  ___| |_ / ___|___ | | (_)___(_) ___  _ __
| |_| |/ _ \/ __| __| |   / _ \| | | / __| |/ _ \| '_ \
|  _  | (_) \__ \ |_| |__| (_) | | | \__ \ | (_) | | | |
|_| |_|\___/|___/\__|\____\___/|_|_|_|___/_|\___/|_| |_|
```

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Go Reference](https://pkg.go.dev/badge/github.com/AbnerEarl/HostCollision.svg)](https://pkg.go.dev/github.com/AbnerEarl/HostCollision)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)]()

---

## 📖 什么是 Host 碰撞？

**Host 碰撞** 是一种资产发现技术，原理基于 HTTP 协议中 `Host` 请求头的特性：

许多 Web 服务器（Nginx、Apache、IIS 等）使用 `Host` 头来区分不同的虚拟主机。当目标站点使用了 **CDN**、**反向代理** 或 **负载均衡** 时，虽然域名解析到 CDN 的 IP，但后端真实服务器可能对特定的 `Host` 头做出不同的响应。

通过向目标 IP 发送携带不同 `Host` 头的 HTTP 请求，对比响应差异，就能发现：

- 🏢 隐藏在 CDN 背后的真实业务系统
- 🔒 未对外公开的内部管理系统
- 📦 同一 IP 上托管的其他域名站点
- 🌐 绕过 CDN 直连源站的通道

```
┌─────────────┐                          ┌─────────────────┐
│   攻击者     │   GET / HTTP/1.1         │   目标 IP       │
│             │   Host: admin.target.com  │                 │
│  HostCollision├────────────────────────►│ Nginx/Apache    │
│             │                           │                 │
│             │◄────────────────────────┤ 200 OK (后台)    │
│  发现资产!   │   返回管理后台页面         │                 │
└─────────────┘                          └─────────────────┘
```

---

## ✨ 项目亮点

### 🚀 高性能 & 轻量化
- **Go 语言实现**，编译为单一静态二进制，无需运行时环境
- **Goroutine 协程池** 并发扫描，充分利用多核性能
- **原子操作计数器** (`sync/atomic`) 替代传统锁，高并发场景零锁竞争
- 跨平台支持 Windows / macOS / Linux，一次编译随处运行

### 📦 双模式架构：命令行 + Go 依赖库
- **命令行工具**：开箱即用，`./hostcollision -h` 即可上手
- **Go 依赖库**：`go get github.com/AbnerEarl/HostCollision`，一行代码集成到你的项目中
- **丰富的公开 API**：`Run()`、`RunWithOptions()`、`RunWithCallback()`、`RunFast()`、`RunStealth()` 等
- **回调机制**：支持实时结果回调和进度回调，方便集成到 Web 服务或自动化流水线

### ⚡ 多维度加速引擎
- **HEAD 预筛选**：用 HEAD 请求替代 GET 做第一轮快速筛选，速度提升 5-10 倍，不支持 HEAD 的服务自动回退
- **TLS 证书 SAN 提取**：TLS 握手提取证书域名，标记为最高优先级 P0，零漏报发现隐藏资产
- **FNV 指纹缓存**：FNV-1a hash 预计算基准响应指纹，O(n) 快速比对替代 O(n*m) 编辑距离
- **自适应分阶段采样**：三阶段逐步采样（50→200→500），无效 IP 更快跳过
- **连接池深度优化**：MaxIdleConnsPerHost 提升至 50，同一 IP 的 Host 请求充分复用 TCP 连接

### 🛡️ 防封禁 & WAF 绕过
- **User-Agent 随机池**：内置 30+ 真实浏览器 UA（Chrome/Firefox/Safari/Edge 多平台多版本），每次请求随机选取
- **令牌桶速率控制**：`-rate 50` 精确限制全局 QPS，避免触发 WAF 限流规则
- **代理池 IP 轮换**：支持从文件加载 HTTP/SOCKS5 代理列表，请求自动轮询切换
- **Header 伪造**：注入 `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` 等绕过头
- **延迟扫描**：请求间随机等待 1~3 秒（可配置），模拟人类行为规避检测
- **请求头混淆**：模拟真实浏览器的 Accept / Accept-Language / Cache-Control 等完整请求头

### 🎯 多重误报过滤
- **请求长度校验**：空响应 / 异常长度初筛
- **内容包含匹配**：碰撞响应 vs 基准响应 vs 错误请求的内容交叉比对
- **Title 标题匹配**：网页标题级别的差异检测
- **编辑距离相似度**：基于 Levenshtein 算法的页面相似度计算（默认阈值 70%）
- **数据样本比对**：多次采样建立基线，有效排除随机内容导致的误报
- **WAF 指纹识别**：自动检测 Server / Body / X-Powered-By 中的 WAF 特征（安全狗、云WAF等）
- **HTTP 状态码白名单**：仅关注有效状态码（200/301/302/404）

### 📊 结果输出
- **实时进度条**：控制台实时显示扫描进度百分比
- **CSV 导出**：UTF-8 BOM 编码，Excel 直接打开无中文乱码
- **TXT 导出**：简洁文本格式，方便 grep 和后续处理
- **实时成功日志**：碰撞成功结果即时输出到控制台
- **优雅退出**：Ctrl+C 安全终止，已有结果自动保存

---

## 📦 安装

### 方式一：作为命令行工具

**前置要求**：[Go 1.21+](https://golang.org/dl/)

```bash
# 克隆项目
git clone https://github.com/AbnerEarl/HostCollision.git
cd HostCollision

# 编译命令行工具
go build -o hostcollision ./cmd/hostcollision/

# 验证
./hostcollision -h
```

### 方式二：作为 Go 依赖库

```bash
go get github.com/AbnerEarl/HostCollision@latest
```

### 方式三：交叉编译

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o hostcollision-linux-amd64 ./cmd/hostcollision/

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o hostcollision-windows-amd64.exe ./cmd/hostcollision/

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o hostcollision-darwin-arm64 ./cmd/hostcollision/
```

---

## 🚀 快速开始（命令行模式）

### 第一步：准备数据文件

编辑 `resource/dataSource/` 目录下的两个文件：

**ipList.txt** — 目标 IP 列表（每行一个）
```
39.156.66.18
180.101.50.242
203.119.169.105
```

**hostList.txt** — 域名列表（每行一个）
```
www.example.com
admin.example.com
api.example.com
mail.example.com
oa.example.com
```

> 💡 **IP 来源建议**：通过子域名收集、空间搜索引擎（Fofa/Shodan/Hunter）、历史 DNS 记录等方式获取目标相关 IP  
> 💡 **域名来源建议**：子域名枚举（Subfinder）、证书透明度日志（crt.sh）、搜索引擎语法等

### 第二步：运行碰撞

```bash
# 使用默认配置运行（推荐新手）
./hostcollision

# 仅扫描 HTTP 协议，2 个线程
./hostcollision -sp http -t 2

# 指定自定义数据文件
./hostcollision -ifp /path/to/my_ips.txt -hfp /path/to/my_hosts.txt
```

### 第三步：查看结果

程序完成后，结果文件生成在当前目录：
- `2026-03-23_xxxxxxxx.csv` — CSV 格式（可用 Excel 打开）
- `2026-03-23_xxxxxxxx.txt` — TXT 格式

同时控制台会输出碰撞成功列表：
```
====================碰 撞 成 功 列 表====================
协议:http://, ip:39.156.66.18, host:admin.example.com, title:管理后台, 匹配成功的数据包大小:15234, 状态码:200 匹配成功
执行完毕 ヾ(≧▽≦*)o
```

---

## 📚 作为 Go 依赖库使用

HostCollision 可以作为 Go 依赖库被其他项目直接引用，无需配置文件即可运行。

### 安装

```bash
go get github.com/AbnerEarl/HostCollision@latest
```

### 示例一：最简单的调用

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    ipList := []string{"1.2.3.4", "5.6.7.8"}
    hostList := []string{"admin.example.com", "api.example.com"}

    // 使用默认配置执行碰撞
    results, err := hostcollision.Run(ipList, hostList)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }

    fmt.Printf("发现 %d 个碰撞成功的资产:\n", len(results))
    for _, r := range results {
        fmt.Println(r.String())
    }
}
```

### 示例二：自定义配置

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    ipList := []string{"1.2.3.4", "5.6.7.8"}
    hostList := []string{"admin.example.com", "api.example.com", "oa.example.com"}

    // 获取默认配置并自定义
    opts := hostcollision.DefaultOptions()
    opts.Protocols = []string{"http://", "https://"}  // 扫描协议
    opts.Threads = 10                                  // 并发数
    opts.RateLimit = 30                                // 每秒最大 30 个请求
    opts.DelayMin = 500                                // 最小延迟 500ms
    opts.DelayMax = 2000                               // 最大延迟 2000ms
    opts.RandomUA = true                               // 启用 UA 随机化
    opts.DataSampleNumber = 15                         // 数据样本 15 次
    opts.SimilarityRatio = 0.8                         // 相似度阈值 80%
    opts.CollisionSuccessStatusCode = "200,302"        // 只关注 200 和 302

    results, err := hostcollision.RunWithOptions(ipList, hostList, opts)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }

    for _, r := range results {
        fmt.Printf("[%s] %s -> %s (title: %s, status: %d)\n",
            r.Protocol, r.IP, r.Host, r.Title, r.MatchStatusCode)
    }
}
```

### 示例三：实时回调模式

适用于需要实时处理结果的场景（如写入数据库、发送通知等）：

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    ipList := []string{"1.2.3.4", "5.6.7.8"}
    hostList := []string{"admin.example.com", "api.example.com"}

    opts := hostcollision.DefaultOptions()
    opts.Threads = 4

    // 设置实时结果回调
    opts.OnResult = func(r *hostcollision.Result) {
        fmt.Printf("🎯 发现资产: %s%s (Host: %s, Title: %s)\n",
            r.Protocol, r.IP, r.Host, r.Title)
        // 这里可以写入数据库、发送 Webhook 通知等
    }

    // 设置进度回调
    opts.OnProgress = func(current, total int64) {
        fmt.Printf("\r进度: %d/%d (%.1f%%)", current, total, float64(current)/float64(total)*100)
    }

    err := hostcollision.RunWithCallback(ipList, hostList, opts)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }

    fmt.Println("\n扫描完成!")
}
```

### 示例四：使用代理池

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    ipList := []string{"1.2.3.4"}
    hostList := []string{"admin.example.com", "api.example.com"}

    opts := hostcollision.DefaultOptions()

    // 方式一：直接传入代理列表
    opts.ProxyList = []string{
        "http://192.168.1.1:8080",
        "socks5://192.168.1.3:1080",
        "http://user:pass@192.168.1.2:8080",
    }

    // 方式二：从文件加载代理列表
    // proxies, _ := hostcollision.LoadProxiesFromFile("./proxyList.txt")
    // opts.ProxyList = proxies

    results, err := hostcollision.RunWithOptions(ipList, hostList, opts)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }

    fmt.Printf("发现 %d 个资产\n", len(results))
}
```

### 示例五：快速模式 & 隐蔽模式

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    ipList := []string{"1.2.3.4", "5.6.7.8"}
    hostList := []string{"admin.example.com", "api.example.com"}

    // 快速模式：关闭速率限制、延迟和数据样本，16 线程全速扫描
    results, err := hostcollision.RunFast(ipList, hostList, 16)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }
    fmt.Printf("快速模式: 发现 %d 个资产\n", len(results))

    // 隐蔽模式：低速 + 高延迟 + 代理池
    proxyList := []string{"http://192.168.1.1:8080", "socks5://192.168.1.3:1080"}
    results2, err := hostcollision.RunStealth(ipList, hostList, proxyList)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }
    fmt.Printf("隐蔽模式: 发现 %d 个资产\n", len(results2))
}
```

### 示例六：从文件加载数据

```go
package main

import (
    "fmt"
    "log"

    hostcollision "github.com/AbnerEarl/HostCollision"
)

func main() {
    // 从文件加载 IP 和 Host 列表
    ipList, err := hostcollision.LoadIPsFromFile("./ips.txt")
    if err != nil {
        log.Fatalf("加载 IP 文件失败: %v", err)
    }

    hostList, err := hostcollision.LoadHostsFromFile("./hosts.txt")
    if err != nil {
        log.Fatalf("加载 Host 文件失败: %v", err)
    }

    // 执行碰撞
    results, err := hostcollision.Run(ipList, hostList)
    if err != nil {
        log.Fatalf("碰撞失败: %v", err)
    }

    fmt.Printf("发现 %d 个资产\n", len(results))
    for _, r := range results {
        fmt.Println(r.String())
    }
}
```

### 示例七：仅扫描 HTTP 或 HTTPS

```go
// 仅 HTTP
results, err := hostcollision.RunHTTPOnly(ipList, hostList)

// 仅 HTTPS
results, err := hostcollision.RunHTTPSOnly(ipList, hostList)
```

### 公开 API 参考

| 方法 | 说明 |
|------|------|
| `Run(ipList, hostList)` | 使用默认配置执行碰撞 |
| `RunWithOptions(ipList, hostList, opts)` | 使用自定义配置执行碰撞 |
| `RunWithCallback(ipList, hostList, opts)` | 回调模式，实时返回每个成功结果 |
| `RunHTTPOnly(ipList, hostList)` | 仅 HTTP 协议碰撞 |
| `RunHTTPSOnly(ipList, hostList)` | 仅 HTTPS 协议碰撞 |
| `RunFast(ipList, hostList, threads)` | 快速模式（无限速/无延迟/无样本） |
| `RunStealth(ipList, hostList, proxyList)` | 隐蔽模式（低速+高延迟+代理池） |
| `DefaultOptions()` | 获取默认配置选项 |
| `LoadIPsFromFile(path)` | 从文件加载 IP 列表 |
| `LoadHostsFromFile(path)` | 从文件加载 Host 列表 |
| `LoadProxiesFromFile(path)` | 从文件加载代理列表 |

### Options 配置字段

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `Protocols` | `[]string` | `["http://","https://"]` | 扫描协议 |
| `Threads` | `int` | `10` | 并发 goroutine 数 |
| `OutputErrorLog` | `bool` | `false` | 是否输出错误日志 |
| `CollisionSuccessStatusCode` | `string` | `"200,301,302,404"` | 成功状态码白名单 |
| `DataSampleNumber` | `int` | `5` | 数据样本次数（0=关闭） |
| `SimilarityRatio` | `float64` | `0.7` | 相似度阈值（0~1） |
| `RateLimit` | `int` | `100` | 每秒最大请求数（0=不限） |
| `DelayMin` | `int` | `200` | 最小延迟（ms） |
| `DelayMax` | `int` | `800` | 最大延迟（ms） |
| `RandomUA` | `bool` | `true` | UA 随机化 |
| `FakeHeaders` | `bool` | `true` | Header 伪造 |
| `FakeHeadersMap` | `map[string]string` | X-Forwarded-For 等 | 自定义伪造 Header |
| `ProxyList` | `[]string` | `nil` | 代理池地址列表 |
| `SingleProxy` | `string` | `""` | 单一代理地址 |
| `ReadTimeout` | `int` | `10` | 读取超时（秒） |
| `ConnectTimeout` | `int` | `10` | 连接超时（秒） |
| `OnResult` | `func(*Result)` | `nil` | 结果回调 |
| `OnProgress` | `func(int64,int64)` | `nil` | 进度回调 |
| `OnError` | `func(...)` | `nil` | 错误回调 |
| `Blacklists` | `*BlacklistsOption` | 内置 WAF 特征 | WAF 黑名单 |
| `EnableHEADPreFilter` | `*bool` | `true` | HEAD 预筛选（不支持 HEAD 自动回退） |
| `EnableTLSScan` | `*bool` | `true` | TLS 证书 SAN 提取 |
| `TLSScanConcurrency` | `int` | `30` | TLS 扫描并发数 |
| `EnableFingerprintCache` | `*bool` | `true` | FNV hash 指纹缓存快速比对 |
| `EnableAdaptiveSampling` | `*bool` | `true` | 自适应分阶段采样 |
| `OnTLSScanDone` | `func(*TLSScanResult)` | `nil` | TLS 扫描完成回调 |

### Result 结果结构

```go
type Result struct {
    Protocol               string // 协议, 如 "http://" 或 "https://"
    IP                     string // IP 地址
    Host                   string // 碰撞成功的 Host
    Title                  string // 网页标题
    MatchContentLen        int    // 碰撞请求的响应大小
    BaseContentLen         int    // 基准请求的响应大小
    ErrorHostContentLen    int    // 绝对错误请求的响应大小
    RelativeHostContentLen int    // 相对错误请求的响应大小
    MatchStatusCode        int    // 碰撞请求的状态码
    BaseStatusCode         int    // 基准请求的状态码
    ErrorHostStatusCode    int    // 绝对错误请求的状态码
    RelativeHostStatusCode int    // 相对错误请求的状态码
}
```

---

## 📋 命令行参数大全

### 基础参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-h` | 显示帮助文档 | — | `-h` |
| `-sp` | 扫描协议（逗号分隔） | `http,https` | `-sp http` |
| `-ifp` | IP 列表文件路径 | `./dataSource/ipList.txt` | `-ifp /tmp/ips.txt` |
| `-hfp` | Host 列表文件路径 | `./dataSource/hostList.txt` | `-hfp /tmp/hosts.txt` |
| `-t` | 最大并发线程数 | `10` | `-t 16` |
| `-o` | 输出格式（逗号分隔） | `csv,txt` | `-o csv` |
| `-ioel` | 是否输出错误日志 | `true` | `-ioel false` |
| `-cssc` | 碰撞成功状态码白名单 | `200,301,302,404` | `-cssc 200,301,302` |
| `-dsn` | 数据样本请求次数（0=关闭） | `5` | `-dsn 0` |

### 防检测参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-rate` | 速率控制：每秒最大请求数（0=不限） | `100` | `-rate 30` |
| `-dmin` | 延迟扫描：最小间隔（毫秒） | `200` | `-dmin 500` |
| `-dmax` | 延迟扫描：最大间隔（毫秒） | `800` | `-dmax 5000` |
| `-ppf` | 代理池文件路径 | — | `-ppf ./proxyList.txt` |
| `-rua` | UA 随机化开关 | `true` | `-rua false` |

### 加速优化参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-head` | HEAD 预筛选开关 | `true` | `-head false` |
| `-tls` | TLS 证书 SAN 提取开关 | `true` | `-tls false` |
| `-fpc` | 基准指纹缓存快速比对开关 | `true` | `-fpc false` |
| `-as` | 自适应分阶段采样开关 | `true` | `-as false` |

> 📝 所有命令行参数的优先级 **高于** 配置文件 `config.yml`

---

## 🔧 常用场景

### 场景一：快速扫描（新手推荐）

```bash
# 最简单的用法，使用默认配置
./hostcollision
```

### 场景二：高速模式（内网/授权测试）

```bash
# 关闭速率限制和延迟，16 线程全速扫描
./hostcollision -rate 0 -dmin 0 -dmax 0 -t 16 -dsn 0
```

### 场景三：低速隐蔽模式（面对严格 WAF）

```bash
# 10 req/s + 2~5 秒随机延迟 + UA 随机 + 代理池
./hostcollision -rate 10 -dmin 2000 -dmax 5000 -rua true -ppf ./resource/dataSource/proxyList.txt -t 2
```

### 场景四：使用代理池

首先编辑代理池文件 `resource/dataSource/proxyList.txt`：
```
http://192.168.1.1:8080
http://user:pass@192.168.1.2:8080
socks5://192.168.1.3:1080
192.168.1.4:8080
```

然后运行：
```bash
./hostcollision -ppf ./resource/dataSource/proxyList.txt
```

### 场景五：只关注特定状态码

```bash
# 只关注 200 和 302
./hostcollision -cssc 200,302
```

### 场景六：关闭数据样本（加速扫描）

```bash
# 关闭数据样本比对（更快但可能增加误报）
./hostcollision -dsn 0
```

### 场景七：仅 HTTPS 扫描

```bash
./hostcollision -sp https -o csv
```

---

## ⚙️ 配置文件详解

配置文件位于 `resource/config.yml`，以下是各配置项的详细说明：

### HTTP 请求配置

```yaml
http:
  readTimeout: 10        # 读取超时（秒）
  connectTimeout: 10     # 连接超时（秒）

  # 单一代理（与代理池互斥，代理池优先）
  proxy:
    isStart: false
    host: "127.0.0.1"
    port: 8080
    username: ""          # 代理认证用户名（可选）
    password: ""          # 代理认证密码（可选）

  # 代理池（启用后忽略单一代理）
  proxyPool:
    isStart: false
    filePath: "./dataSource/proxyList.txt"

  # 扫描协议
  scanProtocol:
    isScanHttp: true
    isScanHttps: true
```

### 碰撞检测配置

```yaml
# 页面相似度阈值（0.7 = 70%）
# 碰撞响应与基准/错误响应相似度超过此值，则认为是误报
similarityRatio: 0.7

# 并发线程数
threadTotal: 10

# 碰撞成功的状态码白名单
collisionSuccessStatusCode: "200,301,302,404"

# 数据样本请求次数（0=关闭，建议 3~5）
dataSample:
  number: 5
```

### WAF 特征黑名单

```yaml
blacklists:
  # Server 头黑名单
  httpServices:
    - "waf"

  # 响应体黑名单（匹配到则判定为 WAF 拦截）
  httpBodies:
    - "服务器安全狗防护验证页面"
    - "该访问行为触发了WAF安全策略"
    - "您没有将此域名或IP绑定到对应站点"
    # ... 更多特征

  # X-Powered-By 头黑名单
  httpXPoweredBy:
    - "waf"
```

### 防检测配置

```yaml
antiDetection:
  randomUA: true          # UA 随机化

  fakeHeaders:            # Header 伪造
    isStart: true
    headers:
      X-Forwarded-For: "127.0.0.1"
      X-Real-IP: "127.0.0.1"
      X-Originating-IP: "127.0.0.1"
      X-Client-IP: "127.0.0.1"
      CF-Connecting-IP: "127.0.0.1"

  rateLimit: 100          # 每秒最大请求数（0=不限）

  delay:                  # 延迟扫描
    isStart: true
    minMs: 200            # 最小间隔（毫秒）
    maxMs: 800            # 最大间隔（毫秒）
```

---

## 🏗️ 项目架构

```
HostCollision/
├── hostcollision.go                     # 📦 公开 API 入口（库模式核心）
├── go.mod                               # Go 模块定义
├── go.sum                               # 依赖校验
├── cmd/
│   └── hostcollision/
│       └── main.go                      # 🖥️ 命令行工具入口
├── resource/
│   ├── config.yml                       # 全局配置文件
│   └── dataSource/
│       ├── ipList.txt                   # IP 列表（用户填写）
│       ├── hostList.txt                 # 域名列表（用户填写）
│       └── proxyList.txt                # 代理池列表（可选）
└── pkg/
    ├── config/
    │   └── config.go                    # 配置管理（YAML 解析、默认配置、多种构造方式）
    ├── collision/
    │   └── collision.go                 # 碰撞核心逻辑：多重误报过滤、WAF 检测、
    │                                    #   HEAD 预筛选、指纹缓存、自适应采样
    ├── httpclient/
    │   └── httpclient.go               # HTTP 客户端：UA 随机池、代理池管理器、
    │                                    #   令牌桶限速器、延迟控制、Header 伪造、
    │                                    #   HEAD 请求、连接池深度优化
    ├── tlsscan/
    │   └── tlsscan.go                   # TLS 证书 SAN 提取：HTTPS 握手、
    │                                    #   证书域名提取、通配符匹配
    ├── dnsfilter/
    │   └── dnsfilter.go                 # DNS 反向筛选：域名解析、IP 段匹配
    ├── diffpage/
    │   └── diffpage.go                  # 页面相似度：HTML 过滤、Levenshtein 编辑距离
    ├── helpers/
    │   └── helpers.go                   # 工具函数：文件读取、数据清洗、路径处理
    └── progress/
        └── progress.go                  # 控制台进度条
```

### 架构说明

```
                     ┌────────────────────────────┐
                     │     外部项目 (调用方)        │
                     └────────────┬───────────────┘
                                  │ go get / import
                     ┌────────────▼───────────────┐
                     │    hostcollision.go         │
                     │  (公开 API: Run / Options)   │
                     └────────────┬───────────────┘
     ┌──────────┬─────────────────┼──────────────────┬──────────┐
     │          │                 │                  │          │
┌────▼────┐ ┌──▼──────────┐ ┌────▼────────┐ ┌──────▼───┐ ┌────▼────────┐
│ config  │ │ collision   │ │ httpclient  │ │ tlsscan  │ │ dnsfilter   │
│ (配置)  │ │ (碰撞核心)  │ │ (HTTP/HEAD) │ │ (TLS证书)│ │ (DNS筛选)   │
└─────────┘ └──────┬──────┘ └─────────────┘ └──────────┘ └─────────────┘
                   │
          ┌────────┼────────┐
          │                 │
    ┌─────▼──────┐   ┌──────▼──────┐
    │ diffpage   │   │ helpers     │
    │ (相似度)   │   │ (工具函数)  │
    └────────────┘   └─────────────┘
```

### 碰撞检测流程（含加速优化）

```mermaid
flowchart TD
    START["输入: IP列表 + Host列表"] --> TLS["TLS证书SAN提取<br/>标记P0优先级"]
    TLS --> DNS["DNS反向筛选<br/>过滤无关Host"]
    DNS --> PRE["IP可达性预检测<br/>过滤不可达IP"]
    PRE --> A["遍历 IP × 协议"]
    A --> B["基准请求: GET protocol://ip"]
    B --> C["错误请求: GET protocol://ip Host=error.xxx.com"]
    C --> D{请求长度校验}
    D -- 异常 --> SKIP[跳过该 IP]
    D -- 正常 --> FP["计算基准FNV指纹"]
    FP --> HEAD{"HEAD预筛选<br/>(不支持HEAD自动回退)"}
    HEAD -- 指纹相同 --> SKIP2[跳过该Host]
    HEAD -- 指纹不同/回退 --> SAMPLE{"自适应采样排除<br/>(50→200→500)"}
    SAMPLE -- 全部相同 --> SKIP3[跳过剩余Host]
    SAMPLE -- 发现差异 --> E["碰撞请求: GET protocol://ip Host=target_host"]
    E --> FNV{"FNV指纹比对<br/>O(n)快速判定"}
    FNV -- hash相同 --> FAIL[匹配失败]
    FNV -- hash不同 --> J{"编辑距离相似度<br/>Levenshtein ≥ 70%?"}
    J -- 相似 --> FAIL
    J -- 不相似 --> F["相对错误请求"]
    F --> K{数据样本比对}
    K -- 命中样本 --> FAIL
    K -- 未命中 --> L{HTTP 状态码白名单}
    L -- 不在白名单 --> FAIL
    L -- 在白名单 --> M{WAF 特征检测}
    M -- 命中 WAF --> RETRY["WAF退避重试"]
    M -- 无 WAF --> SUCCESS["🎉 碰撞成功! 输出结果"]

    style TLS fill:#e6f3ff,stroke:#0066cc
    style HEAD fill:#fff3e6,stroke:#cc6600
    style FNV fill:#e6ffe6,stroke:#006600
    style SAMPLE fill:#f3e6ff,stroke:#6600cc
```

---

## 🧑‍💻 进阶用法

### 自定义 WAF 绕过 Header

在 `config.yml` 中自由添加你需要的伪造 Header：

```yaml
antiDetection:
  fakeHeaders:
    isStart: true
    headers:
      X-Forwarded-For: "127.0.0.1"
      X-Real-IP: "127.0.0.1"
      X-Custom-IP: "10.0.0.1"
      True-Client-IP: "127.0.0.1"
      X-Azure-ClientIP: "127.0.0.1"
```

或者在代码中通过 `Options.FakeHeadersMap` 传入：

```go
opts := hostcollision.DefaultOptions()
opts.FakeHeadersMap = map[string]string{
    "X-Forwarded-For":  "127.0.0.1",
    "True-Client-IP":   "127.0.0.1",
    "X-Azure-ClientIP": "127.0.0.1",
}
```

### 自定义 WAF 特征

如果你遇到了新的 WAF 产品，可以在 `config.yml` 的黑名单中添加特征：

```yaml
blacklists:
  httpBodies:
    - "由Imperva提供安全防护"
    - "请完成验证以继续访问"
    - "Access Denied by Security Policy"
  httpServices:
    - "cloudflare"
    - "akamai"
```

或者在代码中传入：

```go
opts := hostcollision.DefaultOptions()
opts.Blacklists = &hostcollision.BlacklistsOption{
    HTTPServices:   []string{"waf", "cloudflare", "akamai"},
    HTTPBodies:     []string{"Access Denied", "请完成验证"},
    HTTPXPoweredBy: []string{"waf"},
}
```

### 配合其他工具使用

```bash
# 配合 subfinder 自动收集子域名
subfinder -d example.com -silent | tee hosts.txt
./hostcollision -hfp hosts.txt -ifp ips.txt

# 从 Fofa 结果中提取 IP
# fofa 查询: domain="example.com" && country="CN"
cat fofa_results.txt | awk -F',' '{print $1}' | sort -u > ips.txt
./hostcollision -ifp ips.txt
```

---

## ❓ FAQ

### Q: 碰撞出来的结果都是误报怎么办？
A: 尝试以下调整：
1. 提高相似度阈值：`similarityRatio: 0.8`（更严格）
2. 增加数据样本次数：`-dsn 10`
3. 检查并补充 WAF 黑名单特征
4. 调整状态码白名单：`-cssc 200`（只关注 200）

### Q: 扫描速度太慢了？
A: 根据场景调整：
- 增加线程数：`-t 16`
- 关闭延迟扫描：`-dmin 0 -dmax 0`
- 取消速率限制：`-rate 0`
- 关闭数据样本：`-dsn 0`
- 只扫描 HTTP：`-sp http`
- 或者使用库的快速模式：`hostcollision.RunFast(ipList, hostList, 16)`

### Q: 如何避免被目标封 IP？
A: 推荐组合使用：
1. 启用代理池：`-ppf proxyList.txt`
2. 降低速率：`-rate 10`
3. 增大延迟：`-dmin 3000 -dmax 8000`
4. 开启 UA 随机：`-rua true`（默认已开启）
5. 或者使用库的隐蔽模式：`hostcollision.RunStealth(ipList, hostList, proxyList)`

### Q: 代理池文件格式是什么？
A: 每行一个代理地址，支持以下格式：
```
http://ip:port
http://user:pass@ip:port
socks5://ip:port
socks5://user:pass@ip:port
ip:port               # 默认视为 HTTP 代理
```

### Q: CSV 文件 Excel 打开中文乱码？
A: 程序已自动添加 UTF-8 BOM 头，Excel 应能正确识别。如仍有问题，请使用"数据→从文本/CSV"导入功能，手动选择 UTF-8 编码。

### Q: 如何在我的项目中引用？
A: 只需两步：
```bash
# 1. 安装
go get github.com/AbnerEarl/HostCollision@latest
```
```go
// 2. 导入使用
import hostcollision "github.com/AbnerEarl/HostCollision"

results, _ := hostcollision.Run(ipList, hostList)
```


---

## 🚀 性能优化记录

本项目经过两轮深度性能优化，针对大数据量场景（如 19个IP × 2协议 × 1200+个Host ≈ 45,600个碰撞任务）进行了全方位的性能提升和WAF智能绕过增强。

### 第一轮：核心性能优化

> 目标：解决大数据量下执行耗时过长的问题，在不增加线程/协程数量的前提下大幅提升性能。

#### 涉及文件

| 文件 | 优化类型 |
|------|----------|
| `pkg/diffpage/diffpage.go` | 算法优化 + 内存优化 |
| `pkg/httpclient/httpclient.go` | 网络IO优化 + 内存优化 |
| `pkg/collision/collision.go` | 策略优化 + 缓存优化 |
| `hostcollision.go` | CPU优化 + 资源管理 |

#### 1. HTTP 连接池复用（最大性能提升点）

**问题**：原来每次 `SendHTTPGetRequest` 都创建新的 `http.Transport`，导致每次请求都要重新建立 TCP 连接和 TLS 握手。

**优化**：引入 `TransportPool`，按 `IP+协议` 维度复用 Transport：
- 同一个 IP 的不同 Host 请求共享底层 TCP 连接
- TLS 握手只需要做一次
- `Connection: keep-alive` 替代 `Connection: close`
- 读完响应体后自动排空剩余数据确保连接可复用

> 以 19个IP × 2协议 为例，TLS 握手次数从 ~45,600 次降到 38 次。

#### 2. 延迟相对错误请求（减少约50%无效请求）

**问题**：原来每个 Host 碰撞都要发 2 个 HTTP 请求（碰撞请求 + 相对错误请求），但绝大多数 Host 在第一个请求后就能判断失败。

**优化**：将相对错误请求延迟到通过所有轻量级检查之后才发送：
```
碰撞请求 → 状态码检查 → 长度检查 → 内容比对 → 相似度检查 → [通过后才发] 相对错误请求
```

> 假设 95% 的 Host 在轻量级检查阶段就被过滤，实际 HTTP 请求数从 ~91,200 降到 ~47,880。

#### 3. WAF 预检测（避免无效碰撞）

在碰撞前先检查基准请求是否命中 WAF 特征，如果命中则直接跳过该 IP+协议 的所有碰撞，避免浪费请求。

#### 4. 正则表达式预编译

**问题**：`GetFilteredPageContent` 每次调用都编译 6 个正则表达式。

**优化**：将 6 个正则表达式提升为包级别的预编译变量，只编译一次。

> 正则编译次数从 ~820,800 降到 6。

#### 5. 编辑距离算法优化

- **滚动数组**：空间从 `O(n*m)` 降到 `O(min(n,m))`，10KB 文本只需 ~40KB 内存
- **提前终止**：新增 `GetRatioWithThreshold`，当确定相似度不可能达到阈值时立即返回
- **长度差异快速检查**：长度差异超过阈值允许的最大编辑距离时直接返回 0

#### 6. 缓存热点计算

- Worker 初始化时一次性解析状态码白名单和黑名单列表
- `HttpCustomRequest` 增加缓存字段，`AppBody()`/`BodyFormat()`/`Title()` 只计算一次

#### 7. 响应体大小限制

使用 `io.LimitReader` 限制最大读取 512KB，防止大页面导致内存爆炸。

#### 8. 进度监控优化

使用 `time.Ticker` 定时检查（500ms/200ms）替代 `default` 分支忙等待，大幅降低 CPU 占用。

#### 9. 检查顺序优化

遵循**先廉价后昂贵**的原则重排检查顺序：
```
状态码检查(O(1)) → 长度检查(O(1)) → 内容比对(O(n)) → 标题比对(O(1)) → 相似度(O(n*m)) → 相对错误请求 → 样本比对 → WAF检查
```

#### 第一轮优化效果

| 指标 | 优化前 | 优化后 | 提升 |
|------|--------|--------|------|
| TLS 握手次数 | ~45,600 | ~38 | **99.9%↓** |
| HTTP 请求总数 | ~91,200 | ~47,880 | **~47%↓** |
| 正则编译次数 | ~820,800 | 6 | **99.99%↓** |
| 相似度计算内存 | O(n*m) | O(min(n,m)) | **~99%↓** |
| CPU 忙等待 | 持续空转 | 定时检查 | **显著↓** |
| 单次响应体内存 | 无限制 | ≤512KB | **可控** |

---

### 第二轮：WAF 智能绕过优化

> 目标：解决检测到 WAF 就直接放弃所有请求导致丢失大量有价值数据的问题，引入自适应退避和智能重试机制。

#### 核心思想转变

- **之前**：检测到 WAF → 直接放弃整个 IP 的所有 Host 碰撞 ❌
- **现在**：检测到 WAF → 自适应退避 + 指纹变换 + 智能重试 ✅

#### 涉及文件

| 文件 | 修改内容 |
|------|----------|
| `pkg/collision/collision.go` | WAF 自适应退避追踪器 + 智能重试队列 + Host 打散 |
| `pkg/httpclient/httpclient.go` | 请求指纹多样化 + 随机伪造 IP |
| `hostcollision.go` | 集成 WAF 追踪器重置 |

#### 1. WAF 自适应退避追踪器（wafTracker）

每个 `IP+协议` 维度维护一个独立的 WAF 拦截追踪器，根据连续拦截次数动态调整策略：

```
Normal（正常）→ Warning（偶发拦截 1-2次，退避 1-3秒）
    → Backoff（频繁拦截 3-5次，指数退避 3-15秒）
    → Blocked（严重拦截 6-10次，退避 15-30秒）
    → GiveUp（连续 >10次，确认硬封，放弃该IP）
```

连续成功请求会使状态逐步恢复到 Normal。退避时间采用**指数退避 + 随机抖动**策略，避免多个 Worker 同时恢复导致再次触发 WAF。

#### 2. 智能重试队列

被 WAF 拦截的 Host 不会被直接丢弃，而是放入重试队列：

```
第一轮碰撞（打散顺序）
    ├── Host A → 成功 ✓
    ├── Host B → WAF 拦截 → 加入重试队列
    ├── Host C → 成功 ✓
    └── Host D → WAF 拦截 → 加入重试队列

等待 5-15秒 退避

第二轮重试（重新打散 + 额外 2-5秒间隔）
    ├── Host D → 重试成功 ✓
    └── Host B → 重试成功 ✓
```

- 重试前等待 **5-15秒** 随机退避
- 重试队列重新打散顺序
- 每个重试请求之间额外增加 **2-5秒** 随机延迟
- 重试期间如果被硬封（Blocked 状态），立即停止

#### 3. 请求指纹多样化

WAF 通常通过请求指纹（Header 组合、顺序、值）来识别扫描行为。增加了多个维度的随机化：

- **Accept 头变体池**（5种）：不同浏览器发送的 Accept 头略有不同
- **Accept-Language 头变体池**（7种）：涵盖中文、英文、日文等多种语言偏好
- **随机伪造源 IP 池**（10种）：每次请求随机选择 IP 用于 `X-Forwarded-For` 等头部，而不是固定使用 `127.0.0.1`
- **Cache-Control 随机变体**：随机选择 `no-cache` 或 `max-age=0`

#### 4. Host 列表打散

每次碰撞前随机打散 Host 列表顺序，避免按固定模式发送请求，降低被 WAF 基于请求模式识别的风险。

#### 5. 每请求 WAF 实时检测

不再只检测基准请求，而是**每个碰撞请求都进行 WAF 检测**：

- 碰撞请求被 WAF 拦截 → 记录拦截 + 退避 + 加入重试队列
- 相对错误请求被 WAF 拦截 → 跳过相对比对（碰撞请求结果仍有参考价值）
- 新增 **HTTP 429 状态码**检测（明确的频率限制信号）

#### 6. 基准请求 WAF 处理优化

```
基准请求被 WAF 拦截
    ├── 退避等待 → 重试基准请求
    │   ├── 重试成功 → 继续碰撞
    │   └── 重试仍被拦截
    │       ├── 连续 >10次 → 放弃
    │       └── 否则 → 仍然尝试碰撞（不同 Host 可能有不同 WAF 策略）
    └── 不再直接放弃所有 Host
```

#### 第二轮优化效果

| 场景 | 之前 | 现在 |
|------|------|------|
| 某 IP 被 WAF 拦截 | 直接丢失 1200 个 Host 的碰撞机会 | 退避后重试，可能恢复大部分 |
| 频率触发 WAF | 所有后续请求全部浪费 | 自动降速，等待解封后继续 |
| 不同 Host 不同 WAF 策略 | 一刀切放弃 | 逐个尝试，精确识别 |
| 请求指纹被识别 | 所有请求特征一致 | 每次请求指纹不同 |
| 固定请求顺序 | 容易被模式识别 | 随机打散，无规律 |

---

### 第三轮：多维度加速优化

> 目标：在不漏报资产的前提下，通过多层漏斗模型大幅减少无效请求，将碰撞耗时从数小时级降至分钟级。基于前沿技术调研（HTTP HEAD 预筛选、TLS 证书 SAN 提取、FNV-1a 指纹缓存、自适应采样等），从协议层、算法层、架构层三个维度进行全方位加速。

#### 涉及文件

| 文件 | 操作 | 优化类型 |
|------|------|----------|
| `pkg/tlsscan/tlsscan.go` | **新增** | TLS 证书 SAN 提取模块 |
| `pkg/collision/collision.go` | 修改 | HEAD 预筛选 + 指纹缓存 + 自适应采样 |
| `pkg/httpclient/httpclient.go` | 修改 | HEAD 请求方法 + 连接池深度优化 |
| `pkg/config/config.go` | 修改 | 新增优化策略配置字段 |
| `hostcollision.go` | 修改 | TLS 扫描集成 + 新 Options 字段 |
| `cmd/hostcollision/main.go` | 修改 | 新增命令行参数 |
| `resource/config.yml` | 修改 | 新增配置项 |

#### 1. HEAD 预筛选（方案一）— 协议层优化

**核心思想**：用 HTTP HEAD 请求替代 GET 做第一轮快速筛选。HEAD 请求只返回响应头（状态码、Content-Length、Server 等），不返回 Body，**速度比 GET 快 5-10 倍**。

**工作流程**：
```
第1步: 对目标 IP 发送基准 HEAD 请求（无 Host 头）→ 获取基准指纹
第2步: 对目标 IP 发送错误 Host 的 HEAD 请求 → 获取错误指纹
第3步: 对每个候选 Host 发送 HEAD 请求 → 获取 Host 指纹
第4步: 指纹与基准和错误都不同 → 候选，进入 GET 碰撞
       指纹与基准或错误相同 → 大概率无效，跳过
```

**三重安全保障（确保零漏报）**：

| 场景 | 处理策略 |
|------|----------|
| 服务不支持 HEAD（返回 405/501） | 自动回退到全量 GET 碰撞 |
| HEAD 基准请求被 WAF 拦截 | 自动回退到全量 GET 碰撞 |
| HEAD 筛选后候选数量过少（<5%） | 自动回退到全量 GET 碰撞（防止 HEAD/GET 行为不一致导致漏报） |
| HEAD 请求失败的 Host | 保留为候选（安全起见） |
| 某个 Host 返回 405/501 | 保留为候选（可能有特殊路由） |
| 某个 Host 返回 429 | 保留为候选 + 记录 WAF 拦截 |

> 预估可过滤 80-95% 的无效 Host，且完全零漏报。

#### 2. TLS 证书 SAN 提取（方案二）— 协议层优化

**核心思想**：对每个 IP 的 HTTPS 端口做 TLS 握手（不需要完整 HTTP 请求），提取服务器证书中的 **Subject Alternative Name (SAN)** 字段，获取该 IP 上配置的所有域名。

**IP 格式兼容**：

| 输入格式 | 处理方式 |
|----------|----------|
| `1.1.1.1`（纯 IP） | 默认扫描 443 端口 |
| `2.2.2.2:8443`（带端口） | 扫描 8443 端口 |
| `[::1]:8080`（IPv6） | 正确解析 |
| 重复 IP:端口 | 自动去重 |

**匹配策略**：
- 精确匹配：证书域名 `admin.example.com` 与 Host 列表中的 `admin.example.com`
- 通配符匹配：证书域名 `*.example.com` 匹配 Host 列表中的 `sub.example.com`
- 匹配的域名标记为**最高优先级 P0**，排在碰撞列表最前面

> TLS 握手比完整 HTTP 请求快得多，所有 IP 并发握手几十秒内完成。

#### 3. FNV-1a 指纹缓存 + 快速比对（方案三）— 算法层优化

**核心思想**：当前每次碰撞都要做编辑距离计算（`O(n*m)`），对大页面非常慢。引入 FNV-1a hash 指纹做快速预判，只有 hash 不同时才做重量级计算。

**多级比对体系**：
```
Level 1: 状态码 + Content-Length（整数比较，O(1)）  ← 已有
Level 2: FNV-1a Body hash（O(n)，比编辑距离快 100 倍）  ← 新增
Level 3: 编辑距离相似度（O(n*m)，只对 hash 不同的候选执行）  ← 已有
```

**工作原理**：
- 预计算基准响应和错误响应的 FNV-1a 64位 hash 指纹（每个 IP+协议 只算一次，16 字节）
- 碰撞响应先算 FNV hash，与基准比对
- hash 相同 → 内容完全相同 → 直接判定失败（跳过编辑距离计算）
- hash 不同 → 内容一定不同 → 继续做编辑距离相似度计算

**内存开销**：每个 IP+协议 只缓存 2 个 `uint64`（16 字节），2,361 IP × 2 协议 ≈ 75KB，完全可忽略。

> WAF 拦截的响应不影响指纹缓存，WAF 检测在指纹比对之前执行。

#### 4. 连接池深度优化（方案四）— 网络层优化

| 参数 | 优化前 | 优化后 | 说明 |
|------|--------|--------|------|
| `MaxIdleConnsPerHost` | 10 | **50** | 提升同一 IP 的连接复用率 |
| `MaxIdleConns` | 100 | **200** | 增大全局连接池容量 |
| `IdleConnTimeout` | 90s | **60s** | 更快释放闲置连接，减少内存占用 |

同时新增 `SendHTTPHeadRequest` 方法，与 GET 请求共享连接池和所有防检测机制（UA 随机化、Header 伪造、代理池轮换、速率限制）。

#### 5. 自适应分阶段采样（方案五）— 策略层优化

**替代原有的固定采样排除**，分三个阶段逐步增加采样数量：

```
阶段1: 采样 50 个 Host → 全部相同 → 继续阶段2
阶段2: 采样 200 个 Host → 全部相同 → 继续阶段3
阶段3: 采样 500 个 Host → 全部相同 → 跳过该 IP
任何阶段发现不同响应 → 立即进入完整碰撞
```

**WAF 感知**：WAF 拦截的响应**不计入指纹比对**，避免 WAF 统一返回拦截页面导致误判"所有响应相同"。

**内存安全**：只保存一个 `firstFingerprint` 字符串，不缓存所有采样结果。

#### 五层漏斗架构

```mermaid
graph TD
    A["输入数据<br/>IP列表 + Host列表"] --> B{"碰撞组合数 ≤ 阈值?<br/>(默认36万,约1小时)"}
    
    B -->|"是"| C["全量碰撞<br/>跳过所有优化"]
    B -->|"否"| D["启用优化策略"]
    
    D --> E["第1层: TLS证书SAN提取<br/>标记P0优先级<br/>⏱ ~30秒"]
    D --> E2["第1层: DNS反向筛选<br/>过滤无关Host<br/>⏱ ~3分钟"]
    
    E --> F["第2层: IP可达性预检测<br/>过滤不可达IP"]
    E2 --> F
    
    F --> G["第3层: HEAD预筛选<br/>快速过滤无效Host<br/>⏱ 极快"]
    
    G --> H["第4层: 自适应采样排除<br/>无效IP提前跳过"]
    
    H --> I["第5层: 完整GET碰撞<br/>FNV指纹缓存加速<br/>只对候选Host执行"]
    
    I --> J["碰撞结果"]
    C --> J
    
    style E fill:#e6f3ff,stroke:#0066cc
    style G fill:#fff3e6,stroke:#cc6600
    style I fill:#e6ffe6,stroke:#006600
    style H fill:#f3e6ff,stroke:#6600cc
```

#### 新增命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-head` | HEAD 预筛选开关（不支持 HEAD 的服务自动回退） | `true` |
| `-tls` | TLS 证书 SAN 提取开关 | `true` |
| `-fpc` | FNV 指纹缓存快速比对开关 | `true` |
| `-as` | 自适应分阶段采样开关 | `true` |

所有新功能默认开启，可通过参数关闭（如 `-head=false`）。

#### 第三轮优化效果

| 优化层级 | 技术手段 | 过滤率 | 漏报风险 |
|----------|----------|--------|----------|
| TLS 证书 SAN | TLS 握手提取域名，标记 P0 优先级 | — | 零 |
| HEAD 预筛选 | HEAD 响应头指纹比对 | 80-95% | 零（三重安全保障） |
| FNV 指纹缓存 | FNV-1a hash 快速判定相同内容 | — | 零（hash 相同=内容相同） |
| 自适应采样 | 三阶段逐步采样（50→200→500） | 对无效 IP 100% | 极低（WAF 感知） |
| 连接池优化 | MaxIdleConnsPerHost 10→50 | — | 零 |

---

## ⚠️ 免责声明

本工具仅供**合法授权**的安全测试使用。使用者应确保已获得目标系统的授权许可。未经授权擅自对他人系统进行扫描属于违法行为，由此产生的一切法律后果由使用者自行承担，与作者无关。
