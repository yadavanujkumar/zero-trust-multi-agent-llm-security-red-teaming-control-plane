package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// ── Configuration ──────────────────────────────────────────────────────────

type config struct {
	Port             string
	ControlPlaneURL  string
	UpstreamLLMURL   string
	CPTimeoutSeconds int
	MaxBodyBytes     int64
}

func loadConfig() config {
	cpTimeout, _ := strconv.Atoi(getEnv("CONTROL_PLANE_TIMEOUT_SECONDS", "10"))
	maxBody, _ := strconv.ParseInt(getEnv("MAX_BODY_BYTES", "65536"), 10, 64)
	return config{
		Port:             getEnv("PORT", ":8080"),
		ControlPlaneURL:  getEnv("CONTROL_PLANE_URL", "http://localhost:3000"),
		UpstreamLLMURL:   getEnv("UPSTREAM_LLM_URL", ""),
		CPTimeoutSeconds: cpTimeout,
		MaxBodyBytes:     maxBody,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Request / Response types ───────────────────────────────────────────────

type completionRequest struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Model string `json:"model,omitempty"`
}

type controlPlaneReq struct {
	Prompt    string `json:"prompt"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id,omitempty"`
}

type controlPlaneRes struct {
	Status    string   `json:"status"`
	RequestID string   `json:"requestId"`
	Decision  string   `json:"decision"`
	RiskScore float64  `json:"riskScore"`
	Error     string   `json:"error"`
	Reason    string   `json:"reason"`
	Threats   []string `json:"detectedThreats"`
}

// ── HTTP clients ───────────────────────────────────────────────────────────

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 10,
	},
}

// ── Interceptor handler ────────────────────────────────────────────────────

func makeInterceptHandler(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		log := slog.With("requestId", requestID, "method", r.Method, "path", r.URL.Path)
		start := time.Now()

		// Enforce body size limit
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Warn("Failed to read request body — possible size limit exceeded", "error", err)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Request body too large"})
			return
		}

		var payload completionRequest
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			log.Warn("Invalid JSON payload", "error", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
			return
		}

		// Concatenate message content for analysis
		fullPrompt := ""
		for _, msg := range payload.Messages {
			fullPrompt += msg.Content + "\n"
		}
		if fullPrompt == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No message content found"})
			return
		}

		// ── Consult Control Plane ──────────────────────────────────────
		cpReq := controlPlaneReq{
			Prompt:    fullPrompt,
			UserID:    r.Header.Get("X-User-Id"),
			SessionID: r.Header.Get("X-Session-Id"),
		}
		cpBytes, _ := json.Marshal(cpReq)

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.CPTimeoutSeconds)*time.Second)
		defer cancel()

		cpHTTPReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			cfg.ControlPlaneURL+"/api/v1/intercept", bytes.NewBuffer(cpBytes))
		cpHTTPReq.Header.Set("Content-Type", "application/json")
		cpHTTPReq.Header.Set("X-Request-ID", requestID)

		cpResp, err := httpClient.Do(cpHTTPReq)
		if err != nil {
			log.Error("Control plane unreachable — applying fail-safe block", "error", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":     "Security gateway unavailable — request blocked (fail-safe)",
				"requestId": requestID,
			})
			return
		}
		defer cpResp.Body.Close()

		cpBody, _ := io.ReadAll(io.LimitReader(cpResp.Body, 16_384))
		var cpResult controlPlaneRes
		_ = json.Unmarshal(cpBody, &cpResult)

		// ── Block decision ─────────────────────────────────────────────
		if cpResp.StatusCode == http.StatusForbidden {
			log.Warn("Prompt blocked by security policy",
				"riskScore", cpResult.RiskScore,
				"decision", cpResult.Decision,
				"threats", cpResult.Threats,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", requestID)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":          "Request blocked by zero-trust security policy",
				"requestId":      requestID,
				"riskScore":      cpResult.RiskScore,
				"reason":         cpResult.Reason,
				"detectedThreats": cpResult.Threats,
			})
			return
		}

		// ── Allow: proxy to upstream LLM or return mock ────────────────
		elapsed := time.Since(start)
		log.Info("Prompt allowed — forwarding to LLM",
			"decision", cpResult.Decision,
			"riskScore", cpResult.RiskScore,
			"latencyMs", elapsed.Milliseconds(),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Risk-Score", strconv.FormatFloat(cpResult.RiskScore, 'f', 4, 64))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": "Request forwarded to LLM backend.",
					},
					"finish_reason": "stop",
				},
			},
			"requestId": requestID,
		})
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ── Main ───────────────────────────────────────────────────────────────────

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", makeInterceptHandler(cfg))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	srv := &http.Server{
		Addr:         cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("Interceptor listening", "addr", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("Shutting down interceptor...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Forced shutdown", "error", err)
	}
	slog.Info("Interceptor stopped")
}
