package core

import (
	"regexp"
	"strings"
	"unicode"
)

var redactEmailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

var redactKeys = []string{"api_key", "api-key", "apikey", "token", "secret", "password", "passwd", "authorization"}

// RedactText mirrors the Windows source's email, token, then phone substitutions.
func RedactText(text string) string {
	text = redactEmailRE.ReplaceAllString(text, "[REDACTED_EMAIL]")
	runes := []rune(text)
	var tokens strings.Builder
	for i := 0; i < len(runes); {
		keyEnd := tokenKeyEnd(runes, i)
		if keyEnd < 0 {
			tokens.WriteRune(runes[i])
			i++
			continue
		}
		j := keyEnd
		for j < len(runes) && pySpace(runes[j]) {
			j++
		}
		if j == len(runes) || (runes[j] != ':' && runes[j] != '=') {
			tokens.WriteRune(runes[i])
			i++
			continue
		}
		j++
		for j < len(runes) && pySpace(runes[j]) {
			j++
		}
		if j < len(runes) && (runes[j] == '\'' || runes[j] == '"') {
			j++
		}
		valueStart := j
		for j < len(runes) && !pySpace(runes[j]) && runes[j] != '\'' && runes[j] != '"' && runes[j] != '<' && runes[j] != '>' {
			j++
		}
		if j-valueStart < 6 {
			tokens.WriteRune(runes[i])
			i++
			continue
		}
		tokens.WriteString(string(runes[i:keyEnd]))
		tokens.WriteString("=[REDACTED_SECRET]")
		i = j
	}
	return redactPhones(tokens.String())
}

func tokenKeyEnd(runes []rune, i int) int {
	for _, key := range redactKeys {
		if i+len(key) > len(runes) {
			continue
		}
		match := true
		for n, want := range key {
			got := tokenKeyFold(runes[i+n])
			if got != want {
				match = false
				break
			}
		}
		if match {
			return i + len(key)
		}
	}
	return -1
}

func tokenKeyFold(r rune) rune {
	switch r {
	case '\u0130', '\u0131': // Python re.IGNORECASE maps dotted and dotless I to i in [a-z].
		return 'i'
	case '\u017f':
		return 's'
	case '\u212a':
		return 'k'
	default:
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}
}

func pySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

func phoneRune(r rune) bool {
	return unicode.IsDigit(r) || pySpace(r) || r == '(' || r == ')' || r == '.' || r == '-'
}

func redactPhones(text string) string {
	runes := []rune(text)
	var out strings.Builder
	for i := 0; i < len(runes); {
		start := i
		if runes[i] == '+' {
			if i+1 == len(runes) || !unicode.IsDigit(runes[i+1]) {
				out.WriteRune(runes[i])
				i++
				continue
			}
			i++
		} else if !unicode.IsDigit(runes[i]) {
			out.WriteRune(runes[i])
			i++
			continue
		}
		if start > 0 && unicode.IsDigit(runes[start-1]) {
			out.WriteRune(runes[start])
			i = start + 1
			continue
		}
		firstDigit := i
		j := i + 1
		lastDigit := -1
		for j < len(runes) && phoneRune(runes[j]) {
			if unicode.IsDigit(runes[j]) {
				lastDigit = j
			}
			j++
		}
		if lastDigit >= 0 && lastDigit-firstDigit-1 >= 7 && (lastDigit+1 == len(runes) || !unicode.IsDigit(runes[lastDigit+1])) {
			out.WriteString("[REDACTED_PHONE]")
			i = lastDigit + 1
			continue
		}
		out.WriteRune(runes[start])
		i = start + 1
	}
	return out.String()
}
