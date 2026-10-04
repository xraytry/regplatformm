//go:build ignore

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/xiaolajiaoyyds/regplatformm/internal/model"
	"github.com/xiaolajiaoyyds/regplatformm/internal/service"
	"gorm.io/gorm"
)

// kiroValidateMu 每用户验活并发锁，防止同一用户同时触发多个验活流
var kiroValidateMu sync.Map // key: userID (uint), value: *sync.Mutex

// KiroValidateHandler Kiro 账号验活处理器
type KiroValidateHandler struct {
	db        *gorm.DB
	authSvc   *service.AuthService
	proxyPool *service.ProxyPool
}

// NewKiroValidateHandler 创建 Kiro 验活处理器
func NewKiroValidateHandler(db *gorm.DB, authSvc *service.AuthService, proxyPool *service.ProxyPool) *KiroValidateHandler {
	return &KiroValidateHandler{db: db, authSvc: authSvc, proxyPool: proxyPool}
}

// ── AWS OIDC 常量 ──────────────────────────────────────────────────

const (
	oidcTokenURL   = "https://oidc.us-east-1.amazonaws.com/token"
	qUsageLimitURL = "https://q.us-east-1.amazonaws.com/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST"
)

// oidcHeaders 模拟 AWS SDK Rust 的请求头
func oidcHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "aws-sdk-rust/1.3.9 os/windows lang/rust/1.87.0")
	h.Set("x-amz-user-agent", "aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 os/windows lang/rust/1.87.0 m/E app/AmazonQ-For-CLI")
	h.Set("amz-sdk-request", "attempt=1; max=3")
	h.Set("amz-sdk-invocation-id", uuid.New().String())
	return h
}

// qAPIHeaders Q API 验证请求头
func qAPIHeaders(accessToken string) http.Header {
	h := http.Header{}
	h.Set("content-type", "application/x-amz-json-1.0")
	h.Set("authorization", "Bearer "+accessToken)
	h.Set("user-agent", "aws-sdk-rust/1.3.9 ua/2.1 api/codewhispererstreaming/0.1.11582 os/windows lang/rust/1.87.0 md/appVersion-1.19.4 app/AmazonQ-For-CLI")
	h.Set("x-amz-user-agent", "aws-sdk-rust/1.3.9 ua/2.1 api/codewhispererstreaming/0.1.11582 os/windows lang/rust/1.87.0 m/F app/AmazonQ-For-CLI")
	h.Set("x-amzn-codewhisperer-optout", "false")
	h.Set("amz-sdk-request", "attempt=1; max=3")
	h.Set("amz-sdk-invocation-id", uuid.New().String())
	return h
}

// containsAny 检查 s 是否包含 subs 中的任一子串
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// truncateStr 按 rune 截断字符串，避免切断多字节字符
func truncateStr(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "..."
}

// sseWrite 写入一条 SSE 事件
func sseWrite(c *gin.Context, data interface{}) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Warn().Err(err).Msg("SSE JSON 序列化失败")
		return
	}
	if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", jsonBytes); err != nil {
		log.Debug().Err(err).Msg("SSE 写入失败，客户端可能已断开")
	}
}

// validateKiroCredential 验证单个 Kiro 凭证
// 返回 status: "valid" | "suspended" | "expired" | "invalid" | "error"
func validateKiroCredential(ctx context.Context, httpClient *http.Client, clientID, clientSecret, refreshToken string) (string, error) {

	// ── Step1: 刷新 access_token ──
	refreshBody, _ := json.Marshal(map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"refreshToken": refreshToken,
		"grantType":    "refresh_token",
	})

	req, err := http.NewRequestWithContext(ctx, "POST", oidcTokenURL, bytes.NewReader(refreshBody))
	if err != nil {
		return "error", fmt.Errorf("构建刷新请求失败: %w", err)
	}
	req.Header = oidcHeaders()

	resp, err := httpClient.Do(req)
	if err != nil {
		return "error", fmt.Errorf("刷新请求网络错误: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error", fmt.Errorf("读取刷新响应失败: %w", err)
	}
	bodyStr := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		// refresh token 过期或无效
		if containsAny(bodyStr, "invalid_grant", "InvalidGrantException") {
			return "expired", nil
		}
		return "error", fmt.Errorf("刷新失败 HTTP %d: %s", resp.StatusCode, truncateStr(bodyStr, 120))
	}

	// 解析 accessToken
	var tokenResp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil || tokenResp.AccessToken == "" {
		return "error", fmt.Errorf("解析 accessToken 失败")
	}

	// ── Step2: 用 accessToken 调 Q API 检测状态 ──
	qReq, err := http.NewRequestWithContext(ctx, "GET", qUsageLimitURL, nil)
	if err != nil {
		return "error", fmt.Errorf("构建 Q API 请求失败: %w", err)
	}
	qReq.Header = qAPIHeaders(tokenResp.AccessToken)

	qResp, err := httpClient.Do(qReq)
	if err != nil {
		return "error", fmt.Errorf("Q API 网络错误: %w", err)
	}
	defer qResp.Body.Close()

	qBody, err := io.ReadAll(qResp.Body)
	if err != nil {
		return "error", fmt.Errorf("读取 Q API 响应失败: %w", err)
	}
	qStr := string(qBody)

	// 判断状态（按优先级排序）
	if containsAny(qStr, "TEMPORARILY_SUSPENDED") {
		return "suspended", nil
	}
	if qResp.StatusCode == http.StatusUnauthorized || containsAny(qStr, "ExpiredToken", "UnauthorizedException") {
		return "expired", nil
	}
	if containsAny(qStr, "AccessDeniedException", "ValidationException", "ResourceNotFoundException") {
		return "invalid", nil
	}
	if qResp.StatusCode == http.StatusForbidden {
		return "invalid", nil
	}
	if qResp.StatusCode >= 500 {
		return "error", fmt.Errorf("AWS 服务端错误 HTTP %d", qResp.StatusCode)
	}
	if qResp.StatusCode == http.StatusOK {
		return "valid", nil
	}

	return "invalid", fmt.Errorf("未知响应 HTTP %d: %s", qResp.StatusCode, truncateStr(qStr, 120))
}

// SSEValidateKiro 验活 Kiro 账号 SSE 端点（GET /ws/kiro/validate?token=&action=archive|export_archive）
func (h *KiroValidateHandler) SSEValidateKiro(c *gin.Context) {
	// 1. JWT 鉴权（SSE 无法自定义 Header，通过 query token 鉴权）
	token := c.Query("token")
	userID, err := h.authSvc.VerifyJWT(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	// 2. 每用户并发锁——同一用户只能同时运行一个验活流
	userMu, _ := kiroValidateMu.LoadOrStore(userID, &sync.Mutex{})
	kmu := userMu.(*sync.Mutex)
	if !kmu.TryLock() {
		c.JSON(http.StatusConflict, gin.H{"detail": "已有验活任务进行中，请等待完成"})
		return
	}
	defer kmu.Unlock()

	// 3. action 白名单校验
	action := c.DefaultQuery("action", "archive")
	if action != "validate" && action != "archive" && action != "export_archive" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的 action 参数"})
		return
	}

	// 4. scope 参数：active（未归档）/ archived（已归档）
	scope := c.DefaultQuery("scope", "active")
	if scope != "active" && scope != "archived" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的 scope 参数"})
		return
	}
	isArchived := scope == "archived"

	// 5. 查询当前用户的 Kiro 账号（排除已禁用的）
	var results []model.TaskResult
	if err := h.db.Where("user_id = ? AND platform = ? AND is_archived = ? AND disabled = ?", userID, "kiro", isArchived, false).
		Order("created_at ASC").
		Find(&results).Error; err != nil {
		log.Error().Err(err).Uint("user_id", userID).Msg("Kiro 验活查询账号失败")
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "查询账号失败"})
		return
	}

	if len(results) == 0 {
		c.JSON(http.StatusOK, gin.H{"detail": "没有 Kiro 账号需要验证"})
		return
	}

	// 6. SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	ctx := c.Request.Context()
	total := len(results)
	var validCount, invalidCount, errorCount int
	var validResults []model.TaskResult

	// 每批在循环内轮换代理，此处不再预取

	// 发送初始日志
	sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[*] 开始验证 %d 个 Kiro 账号...", total)})
	sseWrite(c, gin.H{"type": "progress", "validated": 0, "total": total, "valid": 0, "invalid": 0})
	c.Writer.Flush()

	// 7. 分批并发验证（每批 5 个，批次间 500ms，每批轮换代理）
	const batchSize = 5
	for i := 0; i < total; i += batchSize {
		// 检查客户端是否断开
		select {
		case <-ctx.Done():
			return
		default:
		}

		end := i + batchSize
		if end > total {
			end = total
		}
		batch := results[i:end]

		// 每批轮换代理，避免所有请求走同一个出口
		var batchProxyURL string
		if p := h.proxyPool.GetNext(); p != nil {
			batchProxyURL = p.HTTP
		}
		batchClient, batchErr := service.BuildProxyHTTPClient(batchProxyURL, 15*time.Second)
		if batchErr != nil {
			log.Warn().Err(batchErr).Msg("构建批次代理客户端失败，回退直连")
			batchClient = &http.Client{Timeout: 15 * time.Second}
		}

		type batchResult struct {
			idx    int
			result model.TaskResult
			status string
		}
		var mu sync.Mutex
		var batchResults []batchResult
		var wg sync.WaitGroup

		for j, r := range batch {
			wg.Add(1)
			go func(idx int, r model.TaskResult) {
				defer wg.Done()

				// 解析 credential_data 提取 clientId/clientSecret/refreshToken
				var cred map[string]interface{}
				if err := json.Unmarshal(r.CredentialData, &cred); err != nil {
					mu.Lock()
					batchResults = append(batchResults, batchResult{idx: idx, result: r, status: "error"})
					mu.Unlock()
					return
				}

				clientID, _ := cred["clientId"].(string)
				clientSecret, _ := cred["clientSecret"].(string)
				refreshToken, _ := cred["refreshToken"].(string)

				if clientID == "" || clientSecret == "" || refreshToken == "" {
					mu.Lock()
					batchResults = append(batchResults, batchResult{idx: idx, result: r, status: "invalid"})
					mu.Unlock()
					return
				}

				status, validateErr := validateKiroCredential(ctx, batchClient, clientID, clientSecret, refreshToken)
				if validateErr != nil {
					log.Warn().Err(validateErr).Str("email", r.Email).Str("status", status).Msg("Kiro 验活异常")
				}

				mu.Lock()
				batchResults = append(batchResults, batchResult{idx: idx, result: r, status: status})
				mu.Unlock()
			}(j, r)
		}
		wg.Wait()

		// 处理本批结果
		now := time.Now()
		for _, br := range batchResults {
			switch br.status {
			case "valid":
				validCount++
				validResults = append(validResults, br.result)
				// 更新 last_validated_at
				if err := h.db.Model(&model.TaskResult{}).Where("id = ? AND user_id = ?", br.result.ID, userID).
					Update("last_validated_at", now).Error; err != nil {
					log.Warn().Err(err).Uint("id", br.result.ID).Msg("更新 last_validated_at 失败")
				}
				sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[+] %s → 正常可用", br.result.Email)})
			case "suspended":
				invalidCount++
				if err := h.db.Model(&model.TaskResult{}).Where("id = ? AND user_id = ?", br.result.ID, userID).
					Updates(map[string]interface{}{"disabled": true, "disabled_reason": "SUSPENDED（已封禁）", "disabled_at": now}).Error; err != nil {
					log.Warn().Err(err).Uint("id", br.result.ID).Msg("禁用封禁账号失败")
				}
				sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[-] %s → 已封禁(SUSPENDED)，已禁用", br.result.Email)})
			case "expired":
				invalidCount++
				if err := h.db.Model(&model.TaskResult{}).Where("id = ? AND user_id = ?", br.result.ID, userID).
					Updates(map[string]interface{}{"disabled": true, "disabled_reason": "Token 过期", "disabled_at": now}).Error; err != nil {
					log.Warn().Err(err).Uint("id", br.result.ID).Msg("禁用过期账号失败")
				}
				sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[-] %s → Token 过期，已禁用", br.result.Email)})
			case "invalid":
				invalidCount++
				if err := h.db.Model(&model.TaskResult{}).Where("id = ? AND user_id = ?", br.result.ID, userID).
					Updates(map[string]interface{}{"disabled": true, "disabled_reason": "账号无效", "disabled_at": now}).Error; err != nil {
					log.Warn().Err(err).Uint("id", br.result.ID).Msg("禁用无效账号失败")
				}
				sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[-] %s → 账号无效，已禁用", br.result.Email)})
			case "error":
				errorCount++
				sseWrite(c, gin.H{"type": "log", "message": fmt.Sprintf("[!] %s → 检测异常(跳过)，可能是 AWS 临时故障", br.result.Email)})
			}
		}

		// 发送进度（已处理总数包含 error 的）
		validated := validCount + invalidCount + errorCount
		sseWrite(c, gin.H{"type": "progress", "validated": validated, "total": total, "valid": validCount, "invalid": invalidCount})
		c.Writer.Flush()

		// 批次间间隔（最后一批不需要）
		if end < total {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// 8. 归档有效账号（仅 scope=active 且 action=archive/export_archive 时执行）
	archivedCount := 0
	if !isArchived && action != "validate" && len(validResults) > 0 {
		var validIDs []uint
		for _, r := range validResults {
			validIDs = append(validIDs, r.ID)
		}
		if err := h.db.Model(&model.TaskResult{}).
			Where("id IN ? AND user_id = ?", validIDs, userID).
			Update("is_archived", true).Error; err != nil {
			log.Error().Err(err).Msg("Kiro 验活归档更新失败")
		} else {
			archivedCount = len(validResults)
		}
	}

	// 9. 构建 complete 事件
	completeData := gin.H{
		"type":     "complete",
		"total":    total,
		"valid":    validCount,
		"invalid":  invalidCount,
		"error":    errorCount,
		"archived": archivedCount,
	}

	// 附带有效账号的 credential_data：export_archive 模式 或 scope=archived 时
	if (action == "export_archive" || isArchived) && len(validResults) > 0 {
		type exportItem struct {
			ID             uint            `json:"id"`
			Email          string          `json:"email"`
			CredentialData json.RawMessage `json:"credential_data"`
		}
		creds := make([]exportItem, 0, len(validResults))
		for _, r := range validResults {
			creds = append(creds, exportItem{
				ID:             r.ID,
				Email:          r.Email,
				CredentialData: json.RawMessage(r.CredentialData),
			})
		}
		completeData["credentials"] = creds
	}

	logMsg := fmt.Sprintf(
		"[+] 验证完成: 共 %d 个，正常 %d 个，失效 %d 个已禁用，异常跳过 %d 个",
		total, validCount, invalidCount, errorCount,
	)
	if archivedCount > 0 {
		logMsg += fmt.Sprintf("，已归档 %d 个", archivedCount)
	}
	sseWrite(c, gin.H{"type": "log", "message": logMsg})
	sseWrite(c, completeData)
	c.Writer.Flush()
}
