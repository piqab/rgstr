package registry

import (
	"encoding/json"
	"net/http"
)

// OCI Distribution Specification error codes.
// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#error-codes
const (
	CodeBlobUnknown         = "BLOB_UNKNOWN"
	CodeBlobUploadInvalid   = "BLOB_UPLOAD_INVALID"
	CodeBlobUploadUnknown   = "BLOB_UPLOAD_UNKNOWN"
	CodeDigestInvalid       = "DIGEST_INVALID"
	CodeManifestBlobUnknown = "MANIFEST_BLOB_UNKNOWN"
	CodeManifestInvalid     = "MANIFEST_INVALID"
	CodeManifestUnknown     = "MANIFEST_UNKNOWN"
	CodeNameInvalid         = "NAME_INVALID"
	CodeNameUnknown         = "NAME_UNKNOWN"
	CodeSizeInvalid         = "SIZE_INVALID"
	CodeUnauthorized        = "UNAUTHORIZED"
	CodeDenied              = "DENIED"
	CodeUnsupported         = "UNSUPPORTED"
	CodeRangeInvalid        = "RANGE_INVALID"
)

type ociError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail,omitempty"`
}

type ociErrorResponse struct {
	Errors []ociError `json:"errors"`
}

// writeError writes a correctly formatted OCI error response.
func writeError(w http.ResponseWriter, status int, code, message string, detail interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ociErrorResponse{
		Errors: []ociError{{Code: code, Message: message, Detail: detail}},
	})
}
