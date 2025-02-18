package libyara

import (
	"fmt"
	"syscall"

	"golang.org/x/text/encoding/ianaindex"
)

var codePageIdentifier = GetSystemANSIEncodePageId()

func DecodeString(data []byte) (string, error) {
	encoding, err := ianaindex.IANA.Encoding(CodePageIdentifierToEncoding[codePageIdentifier])

	if err != nil {
		return "", err
	}

	if encoding == nil {
		return "", fmt.Errorf("ianaindex encoding is nil")
	}

	return encoding.NewDecoder().String(string(data))
}

func EncodeString(data string) ([]byte, error) {
	encoding, err := ianaindex.IANA.Encoding(CodePageIdentifierToEncoding[codePageIdentifier])
	if err != nil {
		return nil, err
	}
	if encoding == nil {
		return nil, fmt.Errorf("ianaindex encoding is nil")
	}
	return encoding.NewEncoder().Bytes([]byte(data))

}

func GetSystemANSIEncodePageId() int {
	// Windows API 获取系统 ANSI 代码页 (GetACP)
	kernel32DLL := syscall.MustLoadDLL("kernel32.dll")
	getACPProc := kernel32DLL.MustFindProc("GetACP")
	codePageID, _, err := getACPProc.Call()
	if err != nil && err != syscall.Errno(0) {
		return 0
	}

	return int(codePageID)
}

var CodePageIdentifierToEncoding = map[int]string{
	28596: "iso-8859-6",
	1256:  "windows-1256",
	28594: "iso-8859-4",
	1257:  "windows-1257",
	28592: "iso-8859-2",
	1250:  "windows-1250",
	936:   "gbk",
	52936: "hz-gb-2312",
	54936: "gb18030",
	950:   "big5",
	28595: "iso-8859-5",
	20866: "koi8-r",
	21866: "koi8-u",
	1251:  "windows-1251",
	28597: "iso-8859-7",
	1253:  "windows-1253",
	38598: "iso-8859-8-i",
	1255:  "windows-1255",
	51932: "euc-jp",
	50220: "iso-2022-jp",
	50221: "csISO2022JP",
	932:   "iso-2022-jp",
	949:   "ks_c_5601-1987",
	51949: "euc-kr",
	28593: "iso-8859-3",
	28605: "iso-8859-15",
	874:   "windows-874",
	28599: "iso-8859-9",
	1254:  "windows-1254",
	65000: "utf-7",
	65001: "utf-8",
	20127: "us-ascii",
	1258:  "windows-1258",
	28591: "iso-8859-1",
	1252:  "Windows-1252",
}
