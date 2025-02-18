package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	libyara "github.com/vela-security/libyara-go/pkg"
)

// TestScanFile01 tests basic file scanning with a single YARA rule.
func TestScanFile01(t *testing.T) {
	yaraDLLPath := filepath.Join("..", "testdata", "libyara64.dll")
	ruleFilePath := filepath.Join("..", "testdata", "test.yar")
	targetFilePath := filepath.Join("..", "testdata", "spy.Bin")

	type ScanResult struct {
		Code  uint32
		Flags uint32
		Rule  string
		Tags  string
	}

	expectedResults := []ScanResult{
		{Code: 1, Flags: 1, Rule: "Backdoor_WebShell_asp", Tags: "ASPXSpy"},
	}

	var scanResults []ScanResult

	scanner := func(yr *libyara.YaraRule) int {
		t.Logf("Match: code=%d, flags=%d, rule=%s, tags=%s", yr.Code, yr.Flags, yr.Rule(), yr.Tag())
		scanResults = append(scanResults, ScanResult{
			Code:  yr.Code,
			Flags: yr.Flags,
			Rule:  yr.Rule(),
			Tags:  yr.Tag(),
		})
		return libyara.CONTINUE
	}

	lib, err := libyara.LazyDLL(yaraDLLPath, libyara.Scanner(scanner))
	if err != nil {
		t.Fatalf("LazyDLL failed: %v", err)
	}

	yara, err := lib.Create()
	if err != nil {
		t.Fatalf("Create Yara failed: %v", err)
	}

	ruleText, err := os.ReadFile(ruleFilePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if err := yara.AddRule(ruleText); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if err := yara.Apply(); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if err := yara.ScanFile(targetFilePath, 0, 10000); err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if !reflect.DeepEqual(scanResults, expectedResults) {
		t.Errorf("Scan results mismatch:\nexpected: %+v\nactual:   %+v", expectedResults, scanResults)
	}

	t.Logf("Scan completed successfully. Results: %+v", scanResults)
}

// TestScanFile02 tests scanning a file with multiple YARA rules.
func TestScanFile02(t *testing.T) {
	// 1. 使用相对路径，方便测试迁移
	yaraDLLPath := filepath.Join("..", "testdata", "libyara64.dll") // 假设 DLL 文件在 testdata 目录下
	ruleFilePath1 := filepath.Join("..", "testdata", "test.yar")
	ruleFilePath2 := filepath.Join("..", "testdata", "test2.yar")
	targetFilePath := filepath.Join("..", "testdata", "spy.Bin")

	type ScanResult struct {
		Code  uint32
		Flags uint32
		Rule  string
		Tags  string
	}

	expectedResults := []ScanResult{
		{Code: 1, Flags: 1, Rule: "Backdoor_WebShell_asp", Tags: "ASPXSpy"},
		{Code: 1, Flags: 2, Rule: "Backdoor_WebShell_asp2", Tags: "ASPXSpy2"},
	}

	var scanResults []ScanResult

	scanner := func(yr *libyara.YaraRule) int {
		t.Logf("Match: code=%d, flags=%d, rule=%s, tags=%s", yr.Code, yr.Flags, yr.Rule(), yr.Tag())
		scanResults = append(scanResults, ScanResult{
			Code:  yr.Code,
			Flags: yr.Flags,
			Rule:  yr.Rule(),
			Tags:  yr.Tag(),
		})
		return libyara.CONTINUE
	}

	lib, err := libyara.LazyDLL(yaraDLLPath, libyara.Scanner(scanner))
	if err != nil {
		t.Fatalf("LazyDLL failed: %v", err)
	}

	yara, err := lib.Create()
	if err != nil {
		t.Fatalf("Create Yara failed: %v", err)
	}

	ruleText1, err := os.ReadFile(ruleFilePath1)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if err := yara.AddRule(ruleText1); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	ruleText2, err := os.ReadFile(ruleFilePath2)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if err := yara.AddRule(ruleText2); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if err := yara.Apply(); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if err := yara.ScanFile(targetFilePath, 0, 10000); err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if !reflect.DeepEqual(scanResults, expectedResults) {
		t.Errorf("Scan results mismatch:\nexpected: %+v\nactual:   %+v", expectedResults, scanResults)
	}

	t.Logf("Scan completed successfully. Results: %+v", scanResults)
}
