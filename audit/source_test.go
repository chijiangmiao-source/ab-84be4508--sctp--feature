package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"sctpaudit/sctp"
)

// 跨两个分片的消息来源: 乱序交付后按消息字节顺序切开, 无重叠、无空洞;
// 字节完全相同的重传不生成第二条来源。
func TestMessageSourceAcrossFragments(t *testing.T) {
	s := NewSession("t-src")
	s.Apply(data(1001, 10, false, false, true, "WORLD!")) // 包0: E片 TSN1001
	s.Apply(data(1000, 10, false, true, false, "HELLO-")) // 包1: B片 TSN1000
	s.Apply(data(1000, 10, false, true, false, "HELLO-")) // 包2: 字节完全相同的重传

	v, err := s.MessageSource(10, 4, 6) // 跨两个分片: [4,10)
	if err != nil {
		t.Fatal(err)
	}
	want := []SourceSegment{
		{MsgStart: 4, MsgEnd: 6, TSN: 1000, PacketIndex: 1, PacketStart: 32, PacketEnd: 34},
		{MsgStart: 6, MsgEnd: 10, TSN: 1001, PacketIndex: 0, PacketStart: 28, PacketEnd: 32},
	}
	gj, _ := json.Marshal(v.Segments)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Fatalf("跨分片来源分段错误:\n%s\n期望:\n%s", gj, wj)
	}
	if v.MessageLength != 12 || v.MessageSeq != 0 || v.SSN != 10 || v.Offset != 4 || v.Length != 6 {
		t.Fatalf("来源视图元信息错误: %+v", v)
	}
	// 分段连续覆盖查询区间: 无重叠、无空洞。
	for i := 1; i < len(v.Segments); i++ {
		if v.Segments[i].MsgStart != v.Segments[i-1].MsgEnd {
			t.Fatalf("分段不连续: %+v", v.Segments)
		}
	}
	// 整条消息: 恰好两段, 重传(包2)不另计, 均指向首次接收的包。
	full, err := s.MessageSource(10, 0, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Segments) != 2 || full.Segments[0].PacketIndex != 1 || full.Segments[1].PacketIndex != 0 {
		t.Fatalf("整条消息来源应恰为两段且指向首次接收包: %+v", full.Segments)
	}
	if full.Segments[0].MsgStart != 0 || full.Segments[0].MsgEnd != 6 ||
		full.Segments[1].MsgStart != 6 || full.Segments[1].MsgEnd != 12 {
		t.Fatalf("整条消息分段未连续覆盖 [0,12): %+v", full.Segments)
	}
	// 单分片内部切片。
	one, err := s.MessageSource(10, 8, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Segments) != 1 || one.Segments[0].MsgStart != 8 || one.Segments[0].MsgEnd != 12 ||
		one.Segments[0].TSN != 1001 || one.Segments[0].PacketStart != 30 || one.Segments[0].PacketEnd != 34 {
		t.Fatalf("单分片来源错误: %+v", one.Segments)
	}
}

// 错误: 超出消息长度、非正长度、负起始、不存在/被跳过/从未交付的流序。
func TestMessageSourceErrors(t *testing.T) {
	s := NewSession("t-src-err")
	s.Apply(data(2000, 20, false, true, false, "AB"))             // B@2000 ssn20
	s.Apply(data(2002, 20, false, false, true, "EF"))             // E@2002 ssn20 (缺 2001)
	s.Apply(fwd(2001, sctp.StreamPair{Stream: testStr, SSN: 20})) // 跨越并作废 ssn20
	s.Apply(data(2003, 21, false, true, true, "OK"))              // 交付 ssn21, 长度 2

	if _, err := s.MessageSource(21, 0, 0); err == nil {
		t.Fatal("非正长度(0)应报错")
	}
	if _, err := s.MessageSource(21, 0, -3); err == nil {
		t.Fatal("非正长度(负)应报错")
	}
	if _, err := s.MessageSource(21, -1, 1); err == nil {
		t.Fatal("负起始字节应报错")
	}
	if _, err := s.MessageSource(21, 2, 1); err == nil {
		t.Fatal("起始字节等于消息长度应报错")
	}
	if _, err := s.MessageSource(21, 1, 2); err == nil { // [1,3) 超出长度 2
		t.Fatal("区间超出消息长度应报错")
	}
	if _, err := s.MessageSource(20, 0, 1); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("已被跳过作废的流序应报不存在: %v", err)
	}
	if _, err := s.MessageSource(22, 0, 1); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("从未交付的流序应报不存在: %v", err)
	}
	// 错误查询不改变冻结状态。
	if len(s.Messages) != 1 || s.Messages[0].SSN != 21 || len(s.Verdicts) != 4 {
		t.Fatalf("错误查询改变了冻结状态: %+v", s.Messages)
	}
}

// 以审计标识重开(模拟服务重启后从新 Store 读取), 来源查询结果一致。
func TestMessageSourceAfterReload(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStore(dir)
	batch := [][]byte{
		data(1001, 10, false, false, true, "WORLD!"),
		data(1000, 10, false, true, false, "HELLO-"),
	}
	if _, _, err := st.Submit("src-reload", batch); err != nil {
		t.Fatal(err)
	}
	first, ok, err := st.Get("src-reload")
	if !ok || err != nil {
		t.Fatalf("读取失败: %v %v", ok, err)
	}
	v1, err := first.MessageSource(10, 2, 8)
	if err != nil {
		t.Fatal(err)
	}

	st2, _ := NewStore(dir) // 全新 Store, 从磁盘恢复
	got, ok, err := st2.Get("src-reload")
	if !ok || err != nil {
		t.Fatalf("恢复失败: %v %v", ok, err)
	}
	v2, err := got.MessageSource(10, 2, 8)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := json.Marshal(v1)
	j2, _ := json.Marshal(v2)
	if string(j1) != string(j2) {
		t.Fatalf("重开后来源查询结果不一致:\n%s\n%s", j1, j2)
	}
}

// HTTP 接口: 来源查询的 200 分段与 400/404 错误。
func TestHTTPMessageSource(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	h := NewHandler(st)
	d1 := data(1000, 10, false, true, false, "HELLO-")
	d2 := data(1001, 10, false, false, true, "WORLD!")
	rec := postJSON(t, h, "/api/audits/src-http/packets", fmt.Sprintf(`{"packets":["%s"]}`, b64s(d2, d1)))
	if rec.Code != 200 {
		t.Fatalf("提交失败: %d %s", rec.Code, rec.Body.String())
	}
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	rec = get("/api/audits/src-http/messages/10/source?offset=4&length=6")
	if rec.Code != 200 {
		t.Fatalf("来源查询应 200: %d %s", rec.Code, rec.Body.String())
	}
	var sv SourceView
	if err := json.Unmarshal(rec.Body.Bytes(), &sv); err != nil {
		t.Fatal(err)
	}
	if len(sv.Segments) != 2 || sv.Segments[0].TSN != 1000 || sv.Segments[0].PacketIndex != 1 ||
		sv.Segments[1].TSN != 1001 || sv.Segments[1].PacketIndex != 0 {
		t.Fatalf("来源分段错误: %+v", sv.Segments)
	}
	cases := []struct {
		path string
		code int
	}{
		{"/api/audits/src-http/messages/10/source?offset=0&length=0", 400},  // 非正长度
		{"/api/audits/src-http/messages/10/source?offset=12&length=1", 400}, // 起始超出消息长度
		{"/api/audits/src-http/messages/10/source?offset=10&length=5", 400}, // 区间超出消息长度
		{"/api/audits/src-http/messages/10/source?offset=0", 400},           // 缺 length
		{"/api/audits/src-http/messages/10/source", 400},                    // 缺参数
		{"/api/audits/src-http/messages/abc/source?offset=0&length=1", 400}, // 流序非法
		{"/api/audits/src-http/messages/99/source?offset=0&length=1", 404},  // 不存在的流序
		{"/api/audits/nope/messages/10/source?offset=0&length=1", 404},      // 审计不存在
	}
	for _, c := range cases {
		if rec := get(c.path); rec.Code != c.code {
			t.Fatalf("%s 应 %d, 实际 %d %s", c.path, c.code, rec.Code, rec.Body.String())
		}
	}
	// 查询后原有内容不变: 逐包裁决与消息列表与首次一致。
	rec = get("/api/audits/src-http")
	var v View
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Messages) != 1 || len(v.Verdicts) != 2 || v.Verdicts[1].Decision != DecisionDelivered {
		t.Fatalf("来源查询后冻结内容被改变: %+v", v)
	}
}
