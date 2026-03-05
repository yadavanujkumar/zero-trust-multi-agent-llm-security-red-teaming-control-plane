package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type CompletionRequest struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type ControlPlaneReq struct {
	Prompt string `json:"prompt"`
	UserID string `json:"user_id"`
}

type ControlPlaneRes struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func main() {
	http.HandleFunc("/v1/chat/completions", interceptHandler)
	port := ":8080"
	log.Printf("Interceptor listening on %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func interceptHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var reqPayload CompletionRequest
	if err := json.Unmarshal(bodyBytes, &reqPayload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Extract full prompt context
	fullPrompt := ""
	for _, msg := range reqPayload.Messages {
		fullPrompt += msg.Content + "\n"
	}

	// Consult Control Plane
	cpReq := ControlPlaneReq{Prompt: fullPrompt, UserID: r.Header.Get("X-User-Id")}
	cpBytes, _ := json.Marshal(cpReq)

	cpURL := os.Getenv("CONTROL_PLANE_URL")
	if cpURL == "" {
		cpURL = "http://localhost:3000"
	}

	cpResp, err := http.Post(cpURL+"/api/v1/intercept", "application/json", bytes.NewBuffer(cpBytes))
	if err != nil {
		http.Error(w, "Control plane unreachable", http.StatusBadGateway)
		return
	}
	defer cpResp.Body.Close()

	if cpResp.StatusCode == http.StatusForbidden {
		var resPayload ControlPlaneRes
		json.NewDecoder(cpResp.Body).Decode(&resPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error": "Security Block: %s"}`, resPayload.Reason)
		return
	}

	// If allowed, normally proxy to real LLM (OpenAI/Anthropic)
	// For boilerplate, we return a mock success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"choices": [{"message": {"role": "assistant", "content": "Proxy allowed request."}}]}`)
}