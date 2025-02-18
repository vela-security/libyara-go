package main

import (
	"testing"

	libyara "github.com/vela-security/libyara-go/pkg"
)

func TestGetSystemANSIEncodePageId(t *testing.T) {
	// 正常情况
	codePageID := libyara.GetSystemANSIEncodePageId()

	if codePageID <= 0 {
		t.Fatalf("Expected a positive code page ID, got: %d", codePageID)
	}

	t.Logf("codePageID:%d encoding:%s", codePageID, libyara.CodePageIdentifierToEncoding[codePageID])
}
