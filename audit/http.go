package audit

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

//go:embed page.html
var pageHTML []byte

type submitRequest struct {
	Packets []string `json:"packets"`
}

type apiError struct {
	Error    string    `json:"error"`
	Conflict *Conflict `json:"conflict,omitempty"`
}

// NewHandler 返回审计台的 HTTP 处理器:
//
//	GET  /                        操作页
//	GET  /health                  健康响应
//	GET  /api/audits/{id}         按标识重新打开冻结的逐包裁决与消息列表
//	POST /api/audits/{id}/packets 按捕获顺序提交至多 32 个 Base64 包
//	GET  /api/audits/{id}/messages/{ssn}/source?start=&length=
//	                              已交付消息内一段字节的来源定位(消息内区间 / TSN /
//	                              首次接收包序号 / 原始包内区间, 均为半开区间)
func NewHandler(st *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(pageHTML)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/audits/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !ValidID(id) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "审计标识非法: 仅允许 1-64 位字母数字、'-'、'_'"})
			return
		}
		s, ok, err := st.Get(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, apiError{Error: fmt.Sprintf("审计 %s 不存在", id)})
			return
		}
		writeJSON(w, http.StatusOK, s.View())
	})
	mux.HandleFunc("GET /api/audits/{id}/messages/{ssn}/source", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !ValidID(id) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "审计标识非法: 仅允许 1-64 位字母数字、'-'、'_'"})
			return
		}
		ssn64, err := strconv.ParseUint(r.PathValue("ssn"), 10, 16)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("流序非法: %q 不是 0-65535 的整数", r.PathValue("ssn"))})
			return
		}
		start, err := queryInt(r, "start")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		length, err := queryInt(r, "length")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		s, ok, err := st.Get(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, apiError{Error: fmt.Sprintf("审计 %s 不存在", id)})
			return
		}
		src, err := s.MessageSource(uint16(ssn64), start, length)
		if err != nil {
			if errors.Is(err, ErrMessageNotDelivered) {
				writeJSON(w, http.StatusNotFound, apiError{Error: err.Error()})
			} else {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			}
			return
		}
		writeJSON(w, http.StatusOK, src)
	})
	mux.HandleFunc("POST /api/audits/{id}/packets", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !ValidID(id) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "审计标识非法: 仅允许 1-64 位字母数字、'-'、'_'"})
			return
		}
		var req submitRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体不是合法 JSON: " + err.Error()})
			return
		}
		if len(req.Packets) == 0 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "packets 不能为空"})
			return
		}
		if len(req.Packets) > MaxPackets {
			writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("一次至多提交 %d 个包, 实收 %d", MaxPackets, len(req.Packets))})
			return
		}
		raws := make([][]byte, len(req.Packets))
		for i, s := range req.Packets {
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("第 %d 个包 Base64 解码失败: %v", i, err)})
				return
			}
			if len(b) == 0 {
				writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("第 %d 个包为空", i)})
				return
			}
			raws[i] = b
		}
		view, conflict, err := st.Submit(id, raws)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		if conflict != nil {
			writeJSON(w, http.StatusConflict, apiError{
				Error:    fmt.Sprintf("第 %d 个包与已冻结裁决冲突, 提交被拒绝", conflict.Index),
				Conflict: conflict,
			})
			return
		}
		writeJSON(w, http.StatusOK, view)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

// queryInt 读取必需的整数查询参数。
func queryInt(r *http.Request, name string) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, fmt.Errorf("缺少查询参数 %s", name)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("查询参数 %s 非法: %q 不是整数", name, raw)
	}
	return n, nil
}
