# libyara-go

[![Go Reference](about:sanitized)](https://pkg.go.dev/github.com/vela-security/libyara-go/pkg)
[中文文档](README_zh.md)


`libyara-go` is a lightweight, modified encapsulation project that exports interfaces for the `libyara` underlying library. Its biggest highlight is that it **does not depend on CGO**, allowing Go language to easily use `libyara`'s functionalities on Windows and Linux platforms (subsequent releases), achieving a more convenient and efficient calling experience.

## Project Highlights ✨

  * **Pure Go implementation, no CGO required:**  Bid farewell to the compilation and deployment challenges brought by CGO, and enjoy the simplicity and convenience of pure Go. Cross-platform compilation is no longer a concern, making it easy to integrate YARA functionality into your Go applications.
  * **High Performance:**  Optimized specifically for Go language, it performs excellently in rule compilation and scanning speed, meeting your ultimate pursuit of performance.
  * **Easy to Use:**  Provides a simple and intuitive API for quick start, easily applying YARA rules to your Go projects.

## Detailed Description

`libyara-go` has made simple extensions to the [VirusTotal/yara](https://github.com/VirusTotal/yara) official library. By adding two files, `libyara-cgo.h` and `libyara-cgo.c`, it enables Go language to call `libyara` functionalities on Windows and Linux platforms without relying on CGO.

In the Go code part, the project implements a series of corresponding Yara calling methods, providing a simple and intuitive API. These methods are specifically optimized for Go language features and perform excellently in rule compilation and scanning speed. Developers can use these methods to easily apply YARA rules to their own Go projects without worrying about the compilation complexity, performance overhead, and deployment difficulties associated with traditional CGO calls.

Whether it's for malware analysis, threat intelligence detection, or incident response and other security-related work, `libyara-go` can provide an efficient and convenient solution.

🏗 **The project is currently in the initial experimental stage.** It has implemented several of the most commonly used Yara calling methods. We will continue to improve and optimize the project in the future to provide convenience for more security field developers.

The project is currently mainly tested on the Windows platform to solve the problem of difficult compilation when using cgo on Windows. The availability on the Linux platform will be tested later (theoretically feasible).

## Quick Start

### Installation

```bash
go get github.com/vela-security/libyara-go/pkg
```

### Download Dynamic Library

  - Download the `libyara64.dll` file and place it in the project root directory.

> The project provides a compiled `libyara64.dll` (`testdata/libyara64.dll`).
> If you want to manually compile the `libyara64` library, refer to the compilation method of the [VirusTotal/yara](https://github.com/VirusTotal/yara) official library.

### Example Usage

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
    // DLL 路径
    path, _ := filepath.Abs("libyara64.dll")

    // 加载库
    lib, err := libyara.LazyDLL(path, libyara.Console(console), libyara.ErrLog(errlog), libyara.Scanner(scanner))
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

## Additional Resources

**awesome-yara**: InQuest has compiled a comprehensive list of YARA-related resources, which is worth checking out.

## Contributing

The project is currently only in the initial experimental stage. We warmly welcome community developers to participate in this project. You can contribute in the following ways:

  - Submit code: Fix bugs, add new features, or optimize existing code.
  - Report issues: If you encounter problems during use, please submit an issue on GitHub.
  - Improve documentation: Help us improve the documentation to make it easier for more people to get started.
