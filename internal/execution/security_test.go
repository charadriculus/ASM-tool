package execution

import (
	"reflect"
	"strings"
	"testing"
)

func TestSubprocessSecurityContracts(t *testing.T) {
	if e := ValidateArgs([]string{"nmap", "literal;$(id)"}); e != nil {
		t.Fatal(e)
	}
	if e := ValidateArgs([]string{"tool", "line\nbreak"}); e == nil {
		t.Fatal("accepted line break")
	}
	got := RedactArgs([]string{"nmap", "--token", "s", "--api-key=k", "-H", "Authorization: Bearer x", "https://u:p@example.test/", "--header=Cookie: x"})
	want := []string{"nmap", "--token", "[REDACTED_SECRET]", "--api-key=[REDACTED_SECRET]", "-H", "[REDACTED_SECRET_HEADER]", "https://[REDACTED_CREDENTIALS]@example.test/", "--header=[REDACTED_SECRET_HEADER]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redaction %v", got)
	}
	env := sanitizeEnv([]string{"PATH=/bin", "HOME=/old", "API_KEY=x", "SSH_AUTH_SOCK=/tmp/s", "LC_ALL=C", "SAFE=value"})
	if strings.Join(env, ",") != "LC_ALL=C,SAFE=value" {
		t.Fatalf("environment %v", env)
	}
	if got := SanitizeFilenameComponent("../bad name;$(x).json"); got != "bad_name_x_.json" {
		t.Fatalf("filename %q", got)
	}
}
