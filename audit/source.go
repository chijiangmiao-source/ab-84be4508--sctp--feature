package audit

import (
	"errors"
	"fmt"

	"sctpaudit/sctp"
)

// ErrMessageNotDelivered 表示所查询的流序不在已交付消息中:
// 该流序已被 FORWARD-TSN 跳过、从未补齐交付, 或根本不存在, 不可作为字节来源查询对象。
var ErrMessageNotDelivered = errors.New("流序不属于已交付消息")

// SourceSegment 是已交付消息内一段连续字节的来源定位。
// 所有区间均为半开区间 [start, end)。
type SourceSegment struct {
	MsgStart    int    `json:"msgStart"`    // 该段在消息内的半开区间起点
	MsgEnd      int    `json:"msgEnd"`      // 该段在消息内的半开区间终点
	TSN         uint32 `json:"tsn"`         // 来源 DATA 的 TSN
	PacketIndex int    `json:"packetIndex"` // 该 TSN 首次接收的包序号(捕获顺序)
	PacketStart int    `json:"packetStart"` // 该段用户载荷在原始 SCTP 包中的半开区间起点
	PacketEnd   int    `json:"packetEnd"`   // 该段用户载荷在原始 SCTP 包中的半开区间终点
}

// MessageSourceView 是一次字节来源查询的完整结果:
// 按消息字节顺序切分的连续段, 段间无重叠、无空洞。
type MessageSourceView struct {
	AuditID       string          `json:"auditId"`
	SSN           uint16          `json:"ssn"`
	MessageSeq    int             `json:"messageSeq"`
	MessageLength int             `json:"messageLength"`
	Start         int             `json:"start"`
	Length        int             `json:"length"`
	Segments      []SourceSegment `json:"segments"`
}

// MessageSource 定位已交付消息中半开区间 [start, start+length) 的字节来源。
//
// 来源完全从冻结状态推导: 消息的来源 TSN 序列、每个 TSN 首次接收的包序号
// (Seen 指纹记录)与该包的原始字节; 完全相同重传不产生新的首次记录, 因此
// 不会生成第二条来源。查询结果对同一冻结审计是确定性的, 且不改写任何状态。
func (s *Session) MessageSource(ssn uint16, start, length int) (*MessageSourceView, error) {
	if length <= 0 {
		return nil, fmt.Errorf("长度必须为正整数, 实收 %d", length)
	}
	if start < 0 {
		return nil, fmt.Errorf("起始字节不能为负, 实收 %d", start)
	}
	var msg *Message
	for i := range s.Messages {
		if s.Messages[i].SSN == ssn {
			msg = &s.Messages[i]
			break
		}
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: 流序 %d 已被跳过或从未完整交付", ErrMessageNotDelivered, ssn)
	}
	// 以减法比较避免 start+length 溢出。
	if start > msg.Length || length > msg.Length-start {
		return nil, fmt.Errorf("查询区间 [%d,%d) 超出消息长度 %d", start, start+length, msg.Length)
	}
	end := start + length
	view := &MessageSourceView{
		AuditID:       s.ID,
		SSN:           ssn,
		MessageSeq:    msg.Seq,
		MessageLength: msg.Length,
		Start:         start,
		Length:        length,
		Segments:      []SourceSegment{},
	}
	// 消息字节由来源 TSN 序列的分片按序拼接而成; 逐片求交即得按消息字节
	// 顺序排列、无重叠无空洞的来源段。
	msgOff := 0
	for _, tsn := range msg.TSNs {
		rec, ok := s.Seen[tsn]
		if !ok {
			return nil, fmt.Errorf("冻结记录缺少 TSN %d 的首次接收包, 无法定位来源", tsn)
		}
		p, err := sctp.Parse(s.Raw[rec.Index])
		if err != nil {
			return nil, fmt.Errorf("冻结包 #%d 无法复算: %w", rec.Index, err)
		}
		d, ok := p.Chunk.(*sctp.DataChunk)
		if !ok || d.TSN != tsn {
			return nil, fmt.Errorf("冻结包 #%d 不是 TSN %d 的 DATA 块, 无法定位来源", rec.Index, tsn)
		}
		segStart, segEnd := msgOff, msgOff+len(d.Data)
		if segStart < end && start < segEnd {
			a, b := max(start, segStart), min(end, segEnd)
			view.Segments = append(view.Segments, SourceSegment{
				MsgStart:    a,
				MsgEnd:      b,
				TSN:         tsn,
				PacketIndex: rec.Index,
				PacketStart: d.PayloadOffset + (a - segStart),
				PacketEnd:   d.PayloadOffset + (b - segStart),
			})
		}
		msgOff = segEnd
	}
	if msgOff != msg.Length {
		return nil, fmt.Errorf("冻结记录不自洽: 分片拼接长度 %d 与消息长度 %d 不一致", msgOff, msg.Length)
	}
	return view, nil
}
