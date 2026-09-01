package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type openAIEmbeddingRequest struct {
	Input []string `json:"input"`
	Model string   `json:"model"`
}

type openAIEmbeddingData struct {
	Index     int       `json:"index"`
	Embedding []float32 `json:"embedding"`
}

type openAIEmbeddingResponse struct {
	Data  []openAIEmbeddingData `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Embedder handles vector embeddings via an OpenAI-compatible /v1/embeddings API.
type Embedder struct {
	apiKey string
	model  string
	url    string
	client *http.Client
}

// NewEmbedder creates an Embedder instance.
func NewEmbedder(apiKey, model, url string) *Embedder {
	if model == "" {
		model = "text-embedding-3-small"
	}
	if url == "" {
		url = "https://api.openai.com/v1/embeddings"
	}
	return &Embedder{
		apiKey: apiKey,
		model:  model,
		url:    url,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Embed generates embeddings for a slice of texts.
func (e *Embedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	payload := openAIEmbeddingRequest{
		Input: texts,
		Model: e.model,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embeddings api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading embeddings response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embeddings api returned %d: %s", resp.StatusCode, string(respBody))
	}

	var embResp openAIEmbeddingResponse
	if err := json.Unmarshal(respBody, &embResp); err != nil {
		return nil, fmt.Errorf("parsing embeddings json: %w", err)
	}

	if embResp.Error != nil {
		return nil, fmt.Errorf("embeddings api error: %s", embResp.Error.Message)
	}

	results := make([][]float32, len(texts))
	for _, item := range embResp.Data {
		if item.Index >= 0 && item.Index < len(results) {
			results[item.Index] = item.Embedding
		}
	}

	return results, nil
}

// CosineSimilarity computes the dot product of two normalized vectors.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot float32
	for i := 0; i < len(a); i++ {
		dot += a[i] * b[i]
	}
	return dot
}
