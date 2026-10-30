package upstream

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"
)

// 官方客户端身份伪造（逆向自 CodeArts Agent 26.10.2 插件 + agentkernel Bun 二进制）。
//
// 关键结论（见 research/codebot_ext）：
//   - 官方聊天请求由插件内嵌的 agentkernel（Bun 1.3.14 单文件二进制）发出，
//     fetch 不设 User-Agent，Go 的 Go-http-client/2.0 是明显异类，故显式对齐。
//   - traceid 族 = uuid4 去连字符（32 hex），非纳秒 hex。
//   - hash3 由 kernel 的原生 DLL 计算；kernel 自带 SIGN_DEGRADE 降级路径
//     （签名失败时不带 hash3 直接发送、服务器照常受理），因此伪造层可省略 hash3，
//     与官方降级态完全一致。
//   - plugin-name = `${xf()}_vscode`，公网版 xf()="snap" → "snap_vscode"。
//   - kernel_version = `<plat>-<arch>_<pc>_<pluginName>`，pc 为内核构建代号。
//   - timestamp = kernel 的 wC()：YYYYMMDDTHHMMSSZ。

const (
	officialPluginName    = "snap_vscode"
	officialPluginVersion = "26.10.2"
	officialClientVersion = "26.10.2"
	officialKernelVersion = "win32-x64_1.13.0_snap_vscode"
	officialIDEName       = "VSCode"
	officialIDEVersion    = "1.105.0"
	officialUserAgent     = "Bun/1.3.14"
	machineNamespace      = "hw2api-machine-v1"
)

// MachineIDFor 返回账号级稳定机器指纹（32 hex）。官方 user-session-id 在一次
// IDE 会话内恒定、跨会话轮换；我们以账号为粒度保持恒定，模拟「一号一机」。
func MachineIDFor(uid string) string {
	if uid == "" {
		return hexNoDash()
	}
	h := sha1.Sum([]byte(machineNamespace + ":" + uid))
	return hex.EncodeToString(h[:16])
}

// hexNoDash 官方 No().replace(/-/g,"") 的等价物：32 hex 无连字符。
func hexNoDash() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// kernelTimestamp 官方 wC() 时间戳格式。
func kernelTimestamp() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// OfficialChatHeadersV2 组装官方 AgentKernel 同款完整请求头（SIGN_DEGRADE 态，
// 即无 hash3）。modelID 为规范化后的上游模型名；uid 用于派生稳定机器指纹。
func OfficialChatHeadersV2(token, traceID, language, modelID, uid string) map[string]string {
	if traceID == "" {
		traceID = hexNoDash()
	}
	if language == "" {
		language = "zh-cn"
	}
	nowMs := fmt.Sprintf("%d", time.Now().UnixMilli())
	return map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "text/event-stream",
		"User-Agent":      officialUserAgent,
		"x-auth-token":    token,
		"x-snap-traceid":  traceID,
		"x-ot-trace-id":   traceID,
		"x-ot-span-id":    hexNoDash(),
		"x-ot-session-id": hexNoDash(),
		// 账号级稳定机器指纹（官方为 IDE 会话级稳定）
		"user-session-id":          MachineIDFor(uid),
		"x-ot-parent-session-id":   "",
		"user-msg-id":              hexNoDash(),
		"x-ot-function":            "",
		"x-ot-client-type":         officialIDEName,
		"x-ot-client-version":      officialClientVersion,
		"X-Language":               language,
		"created-time":             nowMs,
		"model-id":                 modelID,
		"model-name":               modelID,
		"plugin-name":              officialPluginName,
		"plugin-version":           officialPluginVersion,
		"ide-name":                 officialIDEName,
		"ide-version":              officialIDEVersion,
		"kernel-version":           officialKernelVersion,
		"app-id":                   "CodeAgent3.0",
		"timestamp":                kernelTimestamp(),
		"depart":                   "",
		"heartbeat-enable":         "true",
		"is_confidential":          "false",
	}
}
