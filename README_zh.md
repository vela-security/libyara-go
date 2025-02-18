# libyara-go

[![Go Reference](https://pkg.go.dev/badge/github.com/vela-security/libyara-go.svg)](https://pkg.go.dev/github.com/vela-security/libyara-go)


`libyara-go` 是一个对 `libyara` 底层库进行接口导出的轻量改动封装项目，它最大的亮点在于**不依赖 CGO** 即可让 Go 语言在 Windows 和 Linux 平台(后续推出)轻松使用 `libyara` 的功能，实现了更加简便和高效的调用体验。

## 项目亮点 ✨
* **纯 Go 实现，无需 CGO:**  告别 CGO 带来的编译和部署难题，享受纯 Go 带来的简洁与便利。跨平台编译不再是困扰，让您的 Go 应用轻松集成 YARA 功能。
* **高性能:**  专为 Go 语言优化，在规则编译和扫描速度上表现出色，满足您对性能的极致追求。
* **易于使用:**  提供简洁直观的 API，快速上手，轻松将 YARA 规则应用到您的 Go 项目中。


## 详细说明 

`libyara-go` 对 [VirusTotal/yara](https://github.com/VirusTotal/yara) 官方库进行了简单扩展，通过添加 `libyara-cgo.h` 和 `libyara-cgo.c` 两个文件，实现了不依赖 CGO 就能在 Windows 和 Linux 平台上让 Go 语言调用 `libyara` 功能。

在 Go 代码部分，项目实现了一系列对应的 Yara 调用方法，提供了简洁直观的 API。这些方法经过专门针对 Go 语言特性优化，在规则编译和扫描速度上表现出色。开发者可以借助这些方法，轻松地将 YARA 规则应用到自己的 Go 项目中，无需担心传统 CGO 调用带来的编译复杂性、性能开销以及部署难度等问题。

无论是进行恶意软件分析、威胁情报检测，还是事件响应等安全领域的工作，`libyara-go` 都能提供高效且便捷的解决方案。

🏗**项目目前处于初步实验阶段**，实现了几个最常用的 Yara 调用方法，后续我们将继续完善和优化项目，为更多的安全领域开发者提供便利。

项目目前主要在windows平台上进行测试，以解决windows平台上使用cgo时编译困难的问题。后面将会测试在linux平台上的可用性（理论上是可行的）。


## 快速上手
### 安装
```bash
go get github.com/vela-security/libyara-go/pkg
```
### 下载动态库
- 下载 `libyara64.dll` 文件，放在项目根目录下。
>项目中提供了编译好的 `libyara64.dll`（`testdata/libyara64.dll`）。  
如果你想手动编译 `libyara64` 库，编译方法参考[VirusTotal/yara](https://github.com/VirusTotal/yara) 官方库的编译方法。

### 使用示例

```golang:example/main.go
package main

import (
    "fmt"
    libyara "github.com/vela-security/libyara-go/pkg"
    "os"
    "path/filepath"
)

func console(s string) {
    fmt.Println(s)
}

func errlog(err int, s string) {
    fmt.Printf("errlog:%d %s\n", err, s)
}

func scanner(yr *libyara.YaraRule) int {
    fmt.Printf("code:%d flags:%d rule:%s tags:%s\n", yr.Code, yr.Flags, yr.Rule(), yr.Tag())
    return libyara.CONTINUE
}

func main() {
	yaraDLLPath := filepath.Join("testdata", "libyara64.dll")

    lib, err := libyara.LazyDLL(yaraDLLPath, libyara.Console(console), libyara.ErrLog(errlog), libyara.Scanner(scanner))
    if err != nil {
        fmt.Printf("libyara lazyDll fail %v\n", err)
        return
    }

    yara, err := lib.Create()
    if err != nil {
        fmt.Println(err)
        return
    }

    rText, _ := os.ReadFile("testdata\\test.yar")
    if e := yara.AddRule(rText); e != nil {
        fmt.Println(e.Error())
        return
    }

    vPath, _ := filepath.Abs("testdata\\spy.Bin")
	text, _ := os.ReadFile(vPath)

	if e := yara.ScanFile(vPath, 0, 10000); e != nil {
		fmt.Println(e.Error())
		return
	}

	println("-------")
	if e := yara.ScanBuff(text); e != nil {
		fmt.Println(e.Error())
		return
	}
}
```
## 额外资源
**awesome-yara**：InQuest 整理了一份全面的 YARA 相关资源列表，值得一看。

## 参与贡献
目前项目只在初步实验阶段，我们热烈欢迎社区开发者参与到这个项目中来，你可以通过以下方式贡献：

- 提交代码：修复 bug、添加新功能或优化现有代码。
- 报告问题：如果你在使用过程中遇到问题，请在 GitHub 上提交 issue。
- 改进文档：帮助我们完善文档，让更多人更容易上手。
