package object

import "testing"

func TestWebAuthnMethodPolicy(t *testing.T) {
	tests := []struct {
		name string
		app  *Application
		want bool
	}{
		{"missing application", nil, false},
		{"legacy enabled", &Application{EnableWebAuthn: true}, true},
		{"legacy disabled", &Application{}, false},
		{"explicit enabled overrides legacy false", &Application{SigninMethods: []*SigninMethod{{Name: "WebAuthn", Rule: "None"}}}, true},
		{"absent method overrides legacy true", &Application{EnableWebAuthn: true, SigninMethods: []*SigninMethod{{Name: "Password", Rule: "All"}}}, false},
		{"hidden method", &Application{EnableWebAuthn: true, SigninMethods: []*SigninMethod{{Name: "WebAuthn", Rule: "Hide password"}}}, false},
		{"legacy hidden method", &Application{EnableWebAuthn: true, SigninMethods: []*SigninMethod{{Name: "WebAuthn", Rule: "Hide-Password"}}}, false},
		{"nil method entry", &Application{EnableWebAuthn: true, SigninMethods: []*SigninMethod{nil}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.app.IsWebAuthnEnabled(); got != tt.want {
				t.Fatalf("enabled = %v, want %v", got, tt.want)
			}
		})
	}
}
