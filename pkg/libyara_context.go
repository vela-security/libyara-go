package libyara

import (
	"fmt"
	"unsafe"
)

type YaraRule struct {
	Code   uint32
	Flags  uint32
	Offset uint32
	Data   YaraString
	Tags   YaraString
}

func (yr *YaraRule) Rule() string {
	return unsafe.String(yr.Data.Data, yr.Data.Size)
}

func (yr *YaraRule) Tag() string {
	return unsafe.String(yr.Tags.Data, yr.Tags.Size)
}

type _YaraContext struct {
	Status   uint32
	RuleSize uint32
	Total    uint32
	Success  uint32
	Failed   uint32
	Compiler uintptr
	Rules    uintptr
}

type YaraContext struct {
	lib     *LibYara
	context *_YaraContext
}

func (yc *YaraContext) Status() uint32 {
	return yc.context.Status
}

func (yc *YaraContext) Ok() bool {
	return yc.context.Status == 200
}

func (yc *YaraContext) Size() uint32 {
	return yc.context.RuleSize
}

func (yc *YaraContext) AddRuleString(v string) error {
	if len(v) == 0 {
		return nil
	}

	rule := []byte(v)
	rc := yc.lib.callback.AddRuleBuff(yc.context, &rule[0], yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("add rule string fail code:%d", rc)
	}
	return nil
}

func (yc *YaraContext) AddRule(rule []byte) error {
	if len(rule) == 0 {
		return fmt.Errorf("not found rule text")
	}
	rc := yc.lib.callback.AddRuleBuff(yc.context, &rule[0], yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("add rule string fail code:%d", rc)
	}
	return nil
}

func (yc *YaraContext) AddRuleFile(path string) error {
	if len(path) == 0 {
		return nil
	}
	v, _ := EncodeString(path)
	rc := yc.lib.callback.AddRuleFile(yc.context, &v[0], nil, yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("add rule file fail code:%d", rc)
	}
	return nil
}

func (yc *YaraContext) Apply() error {
	rc := yc.lib.callback.Apply(yc.context, yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("apply rule fail code:%d", rc)
	}
	return nil
}

func (yc *YaraContext) ScanBuff(v []byte) error {
	if len(v) == 0 {
		return nil
	}
	rc := yc.lib.callback.ScanBuff(yc.context, &v[0], yc.lib.Handler(), yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("scan mem fail code:%d", rc)
	}
	return nil
}

func (yc *YaraContext) ScanFile(path string, flags uint32, timeout uint32) error {
	if len(path) == 0 {
		return nil
	}

	v, _ := EncodeString(path)

	rc := yc.lib.callback.ScanFile(yc.context, &v[0], flags, timeout, yc.lib.Handler(), yc.lib.ErrLog())
	if rc != 1 {
		return fmt.Errorf("scan mem fail code:%d", rc)
	}
	return nil
}
