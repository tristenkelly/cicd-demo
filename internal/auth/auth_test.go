package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		compareErr func(error) bool
	}{
		{
			name:       "missing Authorization header",
			headers:    http.Header{},
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
			compareErr: func(err error) bool { return errors.Is(err, ErrNoAuthHeaderIncluded) },
		},
		{
			name: "malformed header - no space",
			headers: http.Header{
				"Authorization": []string{"ApiKeyABC123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
			compareErr: func(err error) bool {
				return err != nil && err.Error() == "malformed authorization header"
			},
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer ABC123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
			compareErr: func(err error) bool {
				return err != nil && err.Error() == "malformed authorization header"
			},
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey ABC123"},
			},
			wantKey:    "ABC123",
			wantErr:    nil,
			compareErr: func(err error) bool { return err == nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)
			if gotKey != tt.wantKey {
				t.Errorf("expected key: %q, got: %q", tt.wantKey, gotKey)
			}
			if !tt.compareErr(err) {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
