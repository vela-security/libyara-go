package libyara

import (
	"fmt"
	"github.com/ebitengine/purego"
	"syscall"
)

/*
str_t: struct{char *, int}
print: func(str_t *)
error: func(int , str_t)
cb_match: func( uint32_t flags ,str_t *id, str_t *tags)
*/
const (
	CONTINUE = 0
	ABORT    = 1
	ERROR    = 2
)
const (
	CALLBACK_MSG_RULE_MATCHING     = 1
	CALLBACK_MSG_RULE_NOT_MATCHING = 2
	CALLBACK_MSG_SCAN_FINISHED     = 3
	CALLBACK_MSG_IMPORT_MODULE     = 4
	CALLBACK_MSG_MODULE_IMPORTED   = 5
	CALLBACK_MSG_TOO_MANY_MATCHES  = 6
	CALLBACK_MSG_CONSOLE_LOG       = 7
	CALLBACK_MSG_TOO_SLOW_SCANNING = 8
)

type LibYara struct {
	name   string
	dll    *syscall.LazyDLL
	handle uintptr
	option *Option

	callback struct {

		//Create Context
		//cb_print: func(str_t *)
		//errlog: func(int, str_t)
		Create func(ctx *_YaraContext, cb_print uintptr, errlog uintptr) int

		//add rule string
		//errlog: error
		//rule: string
		AddRuleBuff func(ctx *_YaraContext, rule *uint8, errlog uintptr) int

		//add rule file
		//errlog: error
		//path: string
		//namespace: string
		AddRuleFile func(ctx *_YaraContext, path *uint8, namespace *uint8, errlog uintptr) int

		//Rules Parse from compiler
		//errlog: error
		Apply func(ctx *_YaraContext, errlog uintptr) int

		//ScanMem
		//cb_match: func( uint32_t flags,str_t *id, str_t *tags)
		//cb_debug: func( uint32_t flags,str_t *id, str_t *tags)
		//errlog: error
		ScanBuff func(ctx *_YaraContext, buff *uint8, handle uintptr, errlog uintptr) int

		//ScanFile
		ScanFile func(ctx *_YaraContext, path *uint8, flags uint32, timeout uint32, handle uintptr, errlog uintptr) int
		//free
		Free func(ctx *_YaraContext)
	}
}

func (l *LibYara) Create() (*YaraContext, error) {
	var ctx = &_YaraContext{}
	rc := l.callback.Create(ctx, l.Console(), l.ErrLog())
	if rc != 1 {
		return nil, fmt.Errorf("create yara context fail")
	}

	return &YaraContext{context: ctx, lib: l}, nil
}

func (l *LibYara) ErrLog() uintptr {
	return l.option.ErrLog
}

func (l *LibYara) Console() uintptr {
	return l.option.Console
}

func (l *LibYara) Handler() uintptr {
	return l.option.Scanner
}

func LazyDLL(name string, options ...OptionFunc) (*LibYara, error) {
	if len(name) == 0 {
		return nil, fmt.Errorf("name is empty")
	}

	opt := DefaultOption()
	for _, fn := range options {
		fn(opt)
	}
	lib := &LibYara{
		name:   name,
		option: opt,
	}

	dll := syscall.NewLazyDLL(name)
	lib.dll = dll
	lib.handle = dll.Handle()

	purego.RegisterLibFunc(&lib.callback.Create, lib.handle, "yara_create_context_cgo")
	purego.RegisterLibFunc(&lib.callback.AddRuleBuff, lib.handle, "yara_context_add_rule_buff_cgo")
	purego.RegisterLibFunc(&lib.callback.AddRuleFile, lib.handle, "yara_context_add_rule_file_cgo")
	purego.RegisterLibFunc(&lib.callback.Apply, lib.handle, "yara_context_apply_cgo")
	purego.RegisterLibFunc(&lib.callback.ScanBuff, lib.handle, "yara_context_scan_mem_cgo")
	purego.RegisterLibFunc(&lib.callback.ScanFile, lib.handle, "yara_context_scan_file_cgo")
	purego.RegisterLibFunc(&lib.callback.Free, lib.handle, "yara_context_free_cgo")
	return lib, nil
}
