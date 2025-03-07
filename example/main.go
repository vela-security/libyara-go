package main

import (
	"fmt"
	"os"
	"path/filepath"

	libyara "github.com/vela-security/libyara-go/pkg"
)

func console(s string) {
	fmt.Println(s)
}

func errlog(err libyara.ErrNo, s string) {
	fmt.Printf("errlog:%d:%s %s\n", err, err.String(), s)
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

	println("status:", yara.Status())

	rText, _ := os.ReadFile("testdata\\test.yar")
	if e := yara.AddRule(rText); e != nil {
		return
	}

	rPath, _ := filepath.Abs("testdata\\test2.yar")
	fmt.Printf("path:%s\n", rPath)
	if e := yara.AddRuleFile(rPath); e != nil {
		fmt.Println("AddRuleFile ERROR:", e.Error())
		return
	}
	println("size:", yara.Size())

	if e := yara.Apply(); e != nil {
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
