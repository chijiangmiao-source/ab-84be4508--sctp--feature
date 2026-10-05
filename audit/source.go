package audit

import (
	"errors"
	"fmt"

	"sctpaudit/sctp"
)

// ErrMessageNotFound 表示所查流序没有已完整交付的消息
// (已被跳过、从未补齐或根本不存在), 不可作为来源查询对象。
var ErrMessageNotFound = errors.New("消息不存在或从未完整交付")

// SourceSegment 是已交付消息的一段连续字节来源:
// 消息内半开区间 [MsgStart,MsgEnd) 的字节来自 TSN 首次接收的那个包
// (字节完全相同的重传不另计), 对应该原始 SCTP 包中 DATA 用户载荷的
// 半开字节区间 [PacketStart,PacketEnd)。
type SourceSegment struct {
	MsgStart    int    `json:"msgStart"`
	MsgEnd      int    `json:"msgEnd"`
	TSN         uint32 `json:"tsn"`
	PacketIndex int    `json:"packetIndex"`
	PacketStart int    `json:"packetStart"`
	PacketEnd   int    `json:"packetEnd"`
}

// SourceView 是一次消息来源查询的完整结果。分段按消息字节顺序排列,
// 恰好覆盖查询区间 [Offset, Offset+Length), 无重叠、无空洞。
type SourceView struct {
	AuditID       string          `json:"auditId"`
	SSN           uint16          `json:"ssn"`
	MessageSeq    int             `json:"messageSeq"`
	MessageLength int             `json:"messageLength"`
	Offset        int             `json:"offset"`
	Length        int             `json:"length"`
	Segments      []SourceSegment `json:"segments"`
}

// MessageSource 定位已交付消息中 [offset, offset+length) 字节的原始捕获来源。
// 仅读取冻结状态, 不改变任何内容; 同一审计标识的重复查询(含重开后)结果一致。
// 已被跳过或从未完整交付的流序返回 ErrMessageNotFound。
func (s *Session) MessageSource(ssn uint16, offset, length int) (*SourceView, error) {
	if offset < 0 {
		return nil, fmt.Errorf("起始字节不得为负: %d", offset)
	}
	if length <= 0 {
		return nil, fmt.Errorf("长度必须为正: %d", length)
	}
	var msg *Message
	for i := range s.Messages {
		if s.Messages[i].SSN == ssn {
			msg = &s.Messages[i]
			break
		}
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: 流序 %d 已被跳过或从未完整交付, 不可作为查询对象", ErrMessageNotFound, ssn)
	}
	if offset >= msg.Length {
		return nil, fmt.Errorf("起始字节 %d 超出消息长度 %d", offset, msg.Length)
	}
	if offset+length > msg.Length {
		return nil, fmt.Errorf("区间 [%d,%d) 超出消息长度 %d", offset, offset+length, msg.Length)
	}
	// 由冻结的首次接收记录重建消息的分片布局(消息字节顺序 = TSN 升序)。
	type piece struct {
		tsn      uint32
		pktIndex int
		pktStart int // 用户载荷在原始包内的半开区间 [pktStart,pktEnd)
		pktEnd   int
		msgStart int // 该分片在消息内的半开区间 [msgStart,msgEnd)
		msgEnd   int
	}
	pieces := make([]piece, 0, len(msg.TSNs))
	pos := 0
	for _, tsn := range msg.TSNs {
		rec, ok := s.Seen[tsn]
		if !ok {
			return nil, fmt.Errorf("冻结状态不完整: TSN %d 缺少首次接收记录", tsn)
		}
		if rec.Index < 0 || rec.Index >= len(s.Raw) {
			return nil, fmt.Errorf("冻结状态不完整: TSN %d 的包序号 %d 越界", tsn, rec.Index)
		}
		start, end, err := sctp.DataPayloadRange(s.Raw[rec.Index])
		if err != nil {
			return nil, fmt.Errorf("冻结状态不完整: 第 %d 包无法重解析: %w", rec.Index, err)
		}
		n := end - start
		pieces = append(pieces, piece{
			tsn: tsn, pktIndex: rec.Index, pktStart: start, pktEnd: end,
			msgStart: pos, msgEnd: pos + n,
		})
		pos += n
	}
	if pos != msg.Length {
		return nil, fmt.Errorf("冻结状态不一致: 分片合计 %d 字节, 消息长度 %d", pos, msg.Length)
	}
	// 按消息字节顺序切开查询区间: 每段恰好落在一个分片内, 连续无空洞。
	view := &SourceView{
		AuditID: s.ID, SSN: ssn, MessageSeq: msg.Seq, MessageLength: msg.Length,
		Offset: offset, Length: length, Segments: []SourceSegment{},
	}
	end := offset + length
	want := offset
	for _, pc := range pieces {
		lo := max(pc.msgStart, offset)
		hi := min(pc.msgEnd, end)
		if lo >= hi {
			continue
		}
		if lo != want {
			return nil, fmt.Errorf("冻结状态不一致: 消息字节 %d 缺少来源", want)
		}
		shift := lo - pc.msgStart
		view.Segments = append(view.Segments, SourceSegment{
			MsgStart:    lo,
			MsgEnd:      hi,
			TSN:         pc.tsn,
			PacketIndex: pc.pktIndex,
			PacketStart: pc.pktStart + shift,
			PacketEnd:   pc.pktStart + shift + (hi - lo),
		})
		want = hi
	}
	if want != end {
		return nil, fmt.Errorf("冻结状态不一致: 区间 [%d,%d) 未被完全覆盖", offset, end)
	}
	return view, nil
}
