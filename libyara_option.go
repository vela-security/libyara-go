package libyara

import (
	"github.com/ebitengine/purego"
	"unsafe"
)

type Option struct {
	Console uintptr
	ErrLog  uintptr
	Scanner uintptr
}

type OptionFunc func(*Option)

func DefaultOption() *Option {
	return &Option{
		Console: purego.NewCallback(func(*YaraString) int { return 0 }),
		ErrLog:  purego.NewCallback(func(int, *YaraString) int { return 0 }),
	}
}

type YaraString struct {
	Size uint32
	Data *byte
}

func UnsafeYaraString(ptr uintptr) *YaraString {
	dat := (*YaraString)(unsafe.Pointer(ptr))
	return dat
}

func Console(fn func(string)) func(*Option) {
	return func(opt *Option) {
		cb := func(ys *YaraString) int {
			fn(unsafe.String(ys.Data, ys.Size))
			return 0
		}
		opt.Console = purego.NewCallback(cb)
	}
}

func ErrLog(fn func(ErrNo, string)) func(*Option) {
	return func(opt *Option) {
		cb := func(err ErrNo, ys *YaraString) int {
			fn(err, unsafe.String(ys.Data, ys.Size))
			return 0
		}
		opt.ErrLog = purego.NewCallback(cb)
	}
}

func Scanner(fn func(rule *YaraRule) int) func(*Option) {
	return func(opt *Option) {
		opt.Scanner = purego.NewCallback(fn)
	}
}
