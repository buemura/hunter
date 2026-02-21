package api

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the standard error JSON body.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// writeJSON encodes data as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg, Code: status})
}
