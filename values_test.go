package secrets

import (
	_ "embed"
	"sort"
	"strings"
	"testing"
)

//go:embed testdata/secrets.txt
var sampleSecrets string

func TestValues_envs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"missing @all", "@foo=bar | ", "ERR: missing @all=..."},
		{"env typo", "@all=foo bar boz | @fubar=foo ba", "ERR: @fubar: env ba is not among @all"},

		{"conflict", "@all=foo bar boz | @a = foo bar | @b = bar boz | TEST.a = 42 | TEST.b = 10", "ERR: conflicting values with match length 3 for TEST.a and TEST.b when resolving for .bar"},

		{"trivial", "@all=foo bar | TEST=42", "@all = foo bar | @bar = bar | @foo = foo"},
		{"group", "@all=foo bar boz | @fubar=bar foo", "@all = foo bar boz | @bar = bar | @boz = boz | @foo = foo | @fubar = bar foo"},
		{"all defined via subgroup", "@all=prod nonprod | @nonprod = dev stag", "@all = prod dev stag | @dev = dev | @nonprod = dev stag | @prod = prod | @stag = stag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals := New()
			err := vals.ParseString(strings.ReplaceAll(tt.input, "|", "\n"))
			actual := tostr1(vals, err)
			if actual != tt.expected {
				t.Errorf("** ParseString(%q) == %q, expected %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"missing value for env", "@all=foo bar | TEST.foo=42", "ERR: no value for TEST.bar"},

		{"explicit", "@all=foo bar | TEST.foo=42 | TEST.bar=10", "TEST.bar=10 | TEST.foo=42"},
		{"override", "@all=prod nonprod | @nonprod = dev stag | TEST=42 | TEST.nonprod=10", "TEST.dev=10 | TEST.prod=42 | TEST.stag=10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals := New()
			err := vals.ParseString(strings.ReplaceAll(tt.input, "|", "\n"))
			actual := tostr2(vals, err, nil)
			if actual != tt.expected {
				t.Errorf("** %q ==> %q, expected %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestEncryption(t *testing.T) {
	keyring := must(ParseKeyringString(sampleKeyring))

	// t.Fatal(New().EncryptValue("hello", "", "myapp-prod", keyring))

	tests := []struct {
		input    string
		expected string
	}{
		{"@all=foo bar | TEST=secret:myapp-prod:XWDflt8oKe6q1/F7PRpSl79UpaGy2mIm:KQ6NmyIgRTR4hxgwzsq5zpYPryhN", "TEST.bar=hello | TEST.foo=hello"},
	}
	for _, tt := range tests {
		vals := New()
		err := vals.ParseString(strings.ReplaceAll(tt.input, "|", "\n"))
		actual := tostr2(vals, err, keyring)
		if actual != tt.expected {
			t.Errorf("** %q ==> %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestResolve(t *testing.T) {
	keyring := must(ParseKeyringString(sampleKeyring))

	vals, err := ParseString(sampleSecrets)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		env      string
		expected string
	}{
		{"DEFAULT_KEY", "prod", "myapp-prod"},
		{"DEFAULT_KEY", "dev", "myapp-dev"},
		{"DEFAULT_KEY", "all", "myapp-dev"},
		{"DEFAULT_KEY", "nonprod", "myapp-dev"},

		{"FOO", "prod", "4"},
		{"FOO", "stag", "3"},
		{"FOO", "dev", "3"},
		{"FOO", "local-john", "1"},
		{"FOO", "local-bob", "2"},
		{"FOO", "nonprod", "3"},
		{"FOO", "devstag", "3"},
		{"FOO", "local", "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"."+tt.env, func(t *testing.T) {
			actual := tostr3(vals.Value(tt.name, tt.env, keyring))
			if actual != tt.expected {
				t.Errorf("** got %q, expected %q", actual, tt.expected)
			}
		})
	}
}

func tostr1(vals *Values, err error) string {
	if err != nil {
		return "ERR: " + err.Error()
	} else {
		var envs []string
		for k := range vals.resolvedEnvs {
			envs = append(envs, k)
		}
		sort.Strings(envs)

		var lines []string
		for _, env := range envs {
			lines = append(lines, "@"+env+" = "+vals.resolvedEnvs[env].String())
		}

		return strings.Join(lines, " | ")
	}
}

func tostr2(vals *Values, err error, keyring Keyring) string {
	if err != nil {
		return "ERR: " + err.Error()
	} else {
		var envs []string
		for _, k := range vals.validEnvs {
			k = strings.ReplaceAll(k, "*", "example")
			envs = append(envs, k)
		}
		sort.Strings(envs)

		var lines []string
		for _, env := range envs {
			m, err := vals.EnvValues(env, keyring)
			if err != nil {
				return "ERR: " + err.Error()
			}
			for k, v := range m {
				lines = append(lines, k+"."+env+"="+v)
			}
		}
		sort.Strings(lines)

		// "[" + strings.Join(envs, " ") + "] " +
		return strings.Join(lines, " | ")
	}
}

func tostr3(val string, err error) string {
	if err != nil {
		return "ERR: " + err.Error()
	} else {
		return val
	}
}
