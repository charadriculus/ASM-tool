package core

import "testing"

func TestRedactTextSourceGoldens(t *testing.T) {
	tests := []struct{ input, want string }{
		{"Contact alice@example.com or +1 (212) 555-0199; token=abcdef123456", "Contact [REDACTED_EMAIL] or [REDACTED_PHONE]; token=[REDACTED_SECRET]"},
		{"TOKEN : \"abcDEF123\" and password=1234567", "TOKEN=[REDACTED_SECRET]\" and password=[REDACTED_SECRET]"},
		{"Unicode boundary: x١٢٣٤٥٦٧٨٩ y; also ١٢٣٤٥٦٧٨٩z", "Unicode boundary: x[REDACTED_PHONE] y; also [REDACTED_PHONE]z"},
		{"phone boundary 1234567890x 0123456789!", "phone boundary [REDACTED_PHONE]x [REDACTED_PHONE]!"},
		{"email first phone second: a@example.org +44 20 7946 0958", "email first phone second: [REDACTED_EMAIL] [REDACTED_PHONE]"},
		{"key short token=abc untouched; api_key:<>ab cdefgh", "key short token=abc untouched; api_key:<>ab cdefgh"},
		{"Authorization\u2003=\u200b123456 secret", "Authorization=[REDACTED_SECRET] secret"},
		{"prefix١234567890 suffix", "prefix[REDACTED_PHONE] suffix"},
		{"x token='123456 y", "x token=[REDACTED_SECRET] y"},
		{"apİ_key=secret123", "apİ_key=[REDACTED_SECRET]"},
		{"authorİzatİon: secret123", "authorİzatİon=[REDACTED_SECRET]"},
		{"ſecret=secret123", "ſecret=[REDACTED_SECRET]"},
		{"api_Key=secret123", "api_Key=[REDACTED_SECRET]"},
		{"1+123456789", "1+[REDACTED_PHONE]"},
	}
	for _, tt := range tests {
		if got := RedactText(tt.input); got != tt.want {
			t.Errorf("RedactText(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
