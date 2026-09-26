package artifactpromotion

import "time"

// Clock 抽象当前时间，便于测试中控制证明有效期与并发先后顺序。
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// SystemClock 返回使用 time.Now 的时钟。
func SystemClock() Clock { return systemClock{} }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// FixedClock 返回始终返回 t 的时钟，主要用于测试。
func FixedClock(t time.Time) Clock { return fixedClock{t} }
