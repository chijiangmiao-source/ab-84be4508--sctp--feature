package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"sctpaudit/sctp"
)

// 乱序交付的双分片消息: 来源按消息字节顺序切分, 包序号反映首次接收顺序,
// 完全相同重传不生成第二条来源。
func TestMessageSourceOutOfOrder(t *testing.T) {
	s := NewSession("t-src")
	s.Apply(data(1001, 10, false, false, true, "WORLD!")) // 包0: E 片先到
	s.Apply(data(1000, 10, false, true, false, "HELLO-")) // 包1: B 片, 交付
	if v := s.Apply(data(1000, 10, false, true, false, "HELLO-")); v.Decision != DecisionDuplicate {
		t.Fatalf("包2: 完全相同重传应判 duplicate: %+v", v)
	}
	if len(s.Messages) != 1 || s.Messages[0].Length != 12 {
		t.Fatalf("应交付一条 12 字节消息: %+v", s.Messages)
	}

	// 跨两个分片的查询 [4,10): "O-" 来自 TSN 1000, "WORL" 来自 TSN 1001。
	src, err := s.MessageSource(10, 4, 6)
	if err != nil {
		t.Fatal(err)
	}
	want := []SourceSegment{
		{MsgStart: 4, MsgEnd: 6, TSN: 1000, PacketIndex: 1, PacketStart: 32, PacketEnd: 34},
		{MsgStart: 6, MsgEnd: 10, TSN: 1001, PacketIndex: 0, PacketStart: 28, PacketEnd: 32},
	}
	if fmt.Sprintf("%+v", src.Segments) != fmt.Sprintf("%+v", want) {
		t.Fatalf("来源段错误:\n got %+v\nwant %+v", src.Segments, want)
	}
	if src.MessageLength != 12 || src.MessageSeq != 0 || src.SSN != 10 {
		t.Fatalf("来源视图元信息错误: %+v", src)
	}

	// 整条消息: 重传(包2)不得出现, 两段拼接无重叠无空洞。
	full, err := s.MessageSource(10, 0, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Segments) != 2 {
		t.Fatalf("整消息应切为 2 段(重传不生成第二条来源): %+v", full.Segments)
	}
	if full.Segments[0].PacketIndex != 1 || full.Segments[1].PacketIndex != 0 {
		t.Fatalf("包序号应为首次接收序号: %+v", full.Segments)
	}
	if full.Segments[0].MsgEnd != full.Segments[1].MsgStart {
		t.Fatalf("段间不得有空洞或重叠: %+v", full.Segments)
	}

	// 单段查询: 恰好落在一片内。
	one, err := s.MessageSource(10, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Segments) != 1 || one.Segments[0].PacketStart != 33 || one.Segments[0].PacketEnd != 34 {
		t.Fatalf("单段来源错误: %+v", one.Segments)
	}
}

// 三分片乱序消息: 跨三片的查询按消息字节顺序切开, 包内区间逐片对应。
func TestMessageSourceThreeFragments(t *testing.T) {
	s := NewSession("t-src3")
	s.Apply(data(103, 5, false, false, true, "D"))  // 包0: E
	s.Apply(data(101, 5, false, true, false, "AB")) // 包1: B
	s.Apply(data(102, 5, false, false, false, "C")) // 包2: 中间片, 交付 "ABCD"
	if len(s.Messages) != 1 || s.Messages[0].Length != 4 {
		t.Fatalf("应交付 ABCD: %+v", s.Messages)
	}
	src, err := s.MessageSource(5, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []SourceSegment{
		{MsgStart: 1, MsgEnd: 2, TSN: 101, PacketIndex: 1, PacketStart: 29, PacketEnd: 30},
		{MsgStart: 2, MsgEnd: 3, TSN: 102, PacketIndex: 2, PacketStart: 28, PacketEnd: 29},
	}
	if fmt.Sprintf("%+v", src.Segments) != fmt.Sprintf("%+v", want) {
		t.Fatalf("来源段错误:\n got %+v\nwant %+v", src.Segments, want)
	}
	full, err := s.MessageSource(5, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Segments) != 3 || full.Segments[2].PacketIndex != 0 || full.Segments[2].TSN != 103 {
		t.Fatalf("三片整消息来源错误: %+v", full.Segments)
	}
	for i := 1; i < len(full.Segments); i++ {
		if full.Segments[i-1].MsgEnd != full.Segments[i].MsgStart {
			t.Fatalf("段间不得有空洞或重叠: %+v", full.Segments)
		}
	}
}

// 参数与流序错误: 非正长度、负起点、超出消息长度、不存在/被跳过的流序。
func TestMessageSourceErrors(t *testing.T) {
	s := NewSession("t-src-err")
	s.Apply(data(100, 1, false, true, true, "ping"))
	if _, err := s.MessageSource(1, 0, 0); err == nil {
		t.Fatal("长度为 0 应报错")
	}
	if _, err := s.MessageSource(1, 0, -2); err == nil {
		t.Fatal("负长度应报错")
	}
	if _, err := s.MessageSource(1, -1, 2); err == nil {
		t.Fatal("负起点应报错")
	}
	if _, err := s.MessageSource(1, 4, 1); err == nil {
		t.Fatal("起点即消息末尾应报超出消息长度")
	}
	if _, err := s.MessageSource(1, 3, 2); err == nil {
		t.Fatal("区间越界应报超出消息长度")
	}
	if _, err := s.MessageSource(2, 0, 1); !errors.Is(err, ErrMessageNotDelivered) {
		t.Fatalf("不存在的流序应报未交付: %v", err)
	}

	// 被 FORWARD-TSN 跳过的流序: 残缺消息作废, 不可作为查询对象。
	s2 := NewSession("t-src-skip")
	s2.Apply(data(2000, 20, false, true, false, "AB"))
	s2.Apply(data(2002, 20, false, false, true, "EF"))
	s2.Apply(fwd(2001, sctp.StreamPair{Stream: testStr, SSN: 20}))
	if _, err := s2.MessageSource(20, 0, 1); !errors.Is(err, ErrMessageNotDelivered) {
		t.Fatalf("被跳过的流序应报未交付: %v", err)
	}
}

// HTTP 接口: 跨分片查询、参数校验、未知标识/流序, 以及重启后结果一致。
func TestMessageSourceHTTP(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStore(dir)
	h := NewHandler(st)

	d1 := data(1000, 10, false, true, false, "HELLO-")
	d2 := data(1001, 10, false, false, true, "WORLD!")
	body := fmt.Sprintf(`{"packets":["%s"]}`, b64s(d2, d1, d1)) // 乱序 + 完全相同重传
	if rec := postJSON(t, h, "/api/audits/src-http/packets", body); rec.Code != 200 {
		t.Fatalf("提交失败: %d %s", rec.Code, rec.Body.String())
	}

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	rec := get("/api/audits/src-http/messages/10/source?start=4&length=6")
	if rec.Code != 200 {
		t.Fatalf("来源查询应 200: %d %s", rec.Code, rec.Body.String())
	}
	var src MessageSourceView
	if err := json.Unmarshal(rec.Body.Bytes(), &src); err != nil {
		t.Fatal(err)
	}
	want := []SourceSegment{
		{MsgStart: 4, MsgEnd: 6, TSN: 1000, PacketIndex: 1, PacketStart: 32, PacketEnd: 34},
		{MsgStart: 6, MsgEnd: 10, TSN: 1001, PacketIndex: 0, PacketStart: 28, PacketEnd: 32},
	}
	if fmt.Sprintf("%+v", src.Segments) != fmt.Sprintf("%+v", want) {
		t.Fatalf("HTTP 来源段错误:\n got %+v\nwant %+v", src.Segments, want)
	}

	bad := map[string]int{
		"/api/audits/src-http/messages/10/source?start=0":           400, // 缺 length
		"/api/audits/src-http/messages/10/source?length=2":          400, // 缺 start
		"/api/audits/src-http/messages/10/source?start=x&length=2":  400,
		"/api/audits/src-http/messages/10/source?start=0&length=0":  400, // 非正长度
		"/api/audits/src-http/messages/10/source?start=0&length=-1": 400,
		"/api/audits/src-http/messages/10/source?start=-1&length=1": 400,
		"/api/audits/src-http/messages/10/source?start=12&length=1": 400, // 超出消息长度
		"/api/audits/src-http/messages/10/source?start=11&length=2": 400,
		"/api/audits/src-http/messages/xx/source?start=0&length=1":  400, // 流序非法
		"/api/audits/src-http/messages/11/source?start=0&length=1":  404, // 未交付流序
		"/api/audits/nope/messages/10/source?start=0&length=1":      404, // 未知标识
	}
	for path, code := range bad {
		if rec := get(path); rec.Code != code {
			t.Fatalf("GET %s 应 %d, 实际 %d %s", path, code, rec.Code, rec.Body.String())
		}
	}

	// 重启后(全新 Store 从磁盘恢复)来源查询结果逐字节一致。
	st2, _ := NewStore(dir)
	h2 := NewHandler(st2)
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest("GET", "/api/audits/src-http/messages/10/source?start=4&length=6", nil))
	if rec2.Code != 200 || rec2.Body.String() != rec.Body.String() {
		t.Fatalf("恢复后来源查询不一致:\n%s\n%s", rec2.Body.String(), rec.Body.String())
	}
}
