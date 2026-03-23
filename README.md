
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
| `Threads` | `int` | `6` | 并发 goroutine 数 |
| `OutputErrorLog` | `bool` | `false` | 是否输出错误日志 |
| `CollisionSuccessStatusCode` | `string` | `"200,301,302,404"` | 成功状态码白名单 |
| `DataSampleNumber` | `int` | `10` | 数据样本次数（0=关闭） |
| `SimilarityRatio` | `float64` | `0.7` | 相似度阈值（0~1） |
| `RateLimit` | `int` | `50` | 每秒最大请求数（0=不限） |
| `DelayMin` | `int` | `1000` | 最小延迟（ms） |
| `DelayMax` | `int` | `3000` | 最大延迟（ms） |
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
| `-t` | 最大并发线程数 | `6` | `-t 10` |
| `-o` | 输出格式（逗号分隔） | `csv,txt` | `-o csv` |
| `-ioel` | 是否输出错误日志 | `true` | `-ioel false` |
| `-cssc` | 碰撞成功状态码白名单 | `200,301,302,404` | `-cssc 200,301,302` |
| `-dsn` | 数据样本请求次数（0=关闭） | `10` | `-dsn 0` |

### 防检测参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-rate` | 速率控制：每秒最大请求数（0=不限） | `50` | `-rate 30` |
| `-dmin` | 延迟扫描：最小间隔（毫秒） | `1000` | `-dmin 500` |
| `-dmax` | 延迟扫描：最大间隔（毫秒） | `3000` | `-dmax 5000` |
| `-ppf` | 代理池文件路径 | — | `-ppf ./proxyList.txt` |
| `-rua` | UA 随机化开关 | `true` | `-rua false` |

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
threadTotal: 6

# 碰撞成功的状态码白名单
collisionSuccessStatusCode: "200,301,302,404"

# 数据样本请求次数（0=关闭，建议 ≥10）
dataSample:
  number: 10
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

  rateLimit: 50           # 每秒最大请求数（0=不限）

  delay:                  # 延迟扫描
    isStart: true
    minMs: 1000           # 最小间隔（毫秒）
    maxMs: 3000           # 最大间隔（毫秒）
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
    │   └── collision.go                 # 碰撞核心逻辑：多重误报过滤、WAF 检测
    ├── httpclient/
    │   └── httpclient.go               # HTTP 客户端：UA 随机池、代理池管理器、
    │                                    #   令牌桶限速器、延迟控制、Header 伪造
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
           ┌──────────────────────┼──────────────────────┐
           │                      │                      │
┌──────────▼──────────┐ ┌────────▼────────┐ ┌───────────▼──────────┐
│ pkg/config          │ │ pkg/collision   │ │ pkg/httpclient       │
│ (配置管理)           │ │ (碰撞核心逻辑)  │ │ (HTTP客户端/速率/代理) │
└─────────────────────┘ └────────┬────────┘ └──────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │                         │
          ┌─────────▼─────────┐   ┌──────────▼──────────┐
          │ pkg/diffpage      │   │ pkg/helpers          │
          │ (页面相似度算法)    │   │ (文件/数据工具)       │
          └───────────────────┘   └─────────────────────┘
```

### 碰撞检测流程

```mermaid
flowchart TD
    A[开始: 遍历 IP × 协议 × Host] --> B[基准请求: GET protocol://ip]
    B --> C[错误请求: GET protocol://ip Host=error.xxx.com]
    C --> D{请求长度校验}
    D -- 异常 --> SKIP[跳过该 IP]
    D -- 正常 --> E[碰撞请求: GET protocol://ip Host=target_host]
    E --> F[相对错误请求: GET protocol://ip Host=q1w2e3sr4.target_host]
    F --> G{长度校验}
    G -- 异常 --> FAIL[匹配失败]
    G -- 正常 --> H{内容包含匹配}
    H -- 相同 --> FAIL
    H -- 不同 --> I{Title 标题匹配}
    I -- 相同 --> FAIL
    I -- 不同 --> J{相似度检测 Levenshtein ≥ 70%?}
    J -- 相似 --> FAIL
    J -- 不相似 --> K{数据样本比对}
    K -- 命中样本 --> FAIL
    K -- 未命中 --> L{HTTP 状态码白名单}
    L -- 不在白名单 --> FAIL
    L -- 在白名单 --> M{WAF 特征检测}
    M -- 命中 WAF --> FAIL
    M -- 无 WAF --> SUCCESS[🎉 碰撞成功! 输出结果]
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
2. 增加数据样本次数：`-dsn 20`
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

## ⚠️ 免责声明

本工具仅供**合法授权**的安全测试使用。使用者应确保已获得目标系统的授权许可。未经授权擅自对他人系统进行扫描属于违法行为，由此产生的一切法律后果由使用者自行承担，与作者无关。
