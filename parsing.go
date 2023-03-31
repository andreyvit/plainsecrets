package secrets

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	keyNameCharset    = "a-zA-Z0-9_.@-"
	envNameCharset    = "a-zA-Z0-9_-"
	secretNameCharset = "a-zA-Z0-9_"
)

var (
	keyNameRe        = regexp.MustCompile("^[" + keyNameCharset + "]+$")
	secretNameRe     = regexp.MustCompile("^[" + secretNameCharset + "]+$")
	secretWildcardRe = regexp.MustCompile("^[*" + secretNameCharset + "]+$")
	envNameRe        = regexp.MustCompile("^[" + envNameCharset + "]+$")
	envWildcardRe    = regexp.MustCompile("^[*" + envNameCharset + "]+$")
)

func IsValidKeyName(str string) bool {
	return keyNameRe.MatchString(str)
}
func IsValidValueName(str string) bool {
	return secretNameRe.MatchString(str)
}
func IsValidValueNameWildcard(str string) bool {
	return secretWildcardRe.MatchString(str)
}
func IsValidEnvName(str string) bool {
	return envNameRe.MatchString(str)
}
func IsValidEnvNameWildcard(str string) bool {
	return envWildcardRe.MatchString(str)
}

func IsWildcard(env string) bool {
	return strings.ContainsAny(env, "*")
}

func ParseKeyringMap(kv map[string]string) (Keyring, error) {
	keyring := make(Keyring, 0, len(kv))
	for name, v := range kv {
		if !IsValidKeyName(name) {
			return nil, fmt.Errorf("invalid key name %q, must be [%s]+", name, keyNameCharset)
		}
		keyData, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid base64-encoded key: %w", name, err)
		}
		if len(keyData) != KeySize {
			return nil, fmt.Errorf("%s: invalid key size %d, wanted %d", name, len(keyData), KeySize)
		}
		key := &Key{Name: name}
		copy(key.Data[:], keyData)
		keyring = append(keyring, key)
	}
	return keyring, nil
}

func ParseFile(path string) (*Values, error) {
	vals := New()
	err := vals.ParseFile(path)
	return vals, err
}

func ParseString(data string) (*Values, error) {
	vals := New()
	err := vals.ParseString(data)
	return vals, err
}

func (vals *Values) ParseFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = vals.ParseString(string(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func (vals *Values) ParseString(data string) error {
	m, err := parseMultilineKVString(data)
	if err != nil {
		return err
	}
	return vals.ParseMap(m)
}

func (vals *Values) ParseMap(values map[string]string) error {
	for lhs, rhs := range values {
		if groupName, ok := strings.CutPrefix(lhs, "@"); ok {
			g, err := parseEnvGroup(groupName, rhs)
			if err != nil {
				return fmt.Errorf("%w in %q", err, lhs+"="+rhs)
			}
			if vals.envs[groupName] != nil {
				return fmt.Errorf("redefinition of env group %s in %q", groupName, lhs+"="+rhs)
			}
			vals.envs[groupName] = g

		} else {
			name, env, envFound := strings.Cut(lhs, ".")
			if envFound {
				if !IsValidEnvName(env) {
					return fmt.Errorf("malformed env name %q in %q", env, lhs+"="+rhs)
				}
			} else {
				env = All
			}
			if !IsValidValueName(name) {
				return fmt.Errorf("malformed value name %q in %q", env, lhs+"="+rhs)
			}
			e := &entry{
				Env:    env,
				RawLHS: lhs,
				RawRHS: rhs,
			}
			if err := parseValue(rhs, e); err != nil {
				return fmt.Errorf("%w in %q", err, lhs+"="+rhs)
			}
			vals.entries[name] = append(vals.entries[name], e)
		}
	}

	return vals.rebuild()
}

func parseEnvList(str string) (negated bool, items []string, err error) {
	if s, ok := strings.CutPrefix(str, "!"); ok {
		negated = true
		str = strings.TrimSpace(s)
	}

	items = strings.Fields(str)
	for _, env := range items {
		if !IsValidEnvNameWildcard(env) {
			err = fmt.Errorf("malformed env name %q", env)
			return
		}
	}
	return
}

func parseEnvGroup(groupName string, listStr string) (*envGroup, error) {
	if !IsValidEnvName(groupName) {
		return nil, fmt.Errorf("malformed env group name %q", groupName)
	}
	g := &envGroup{}
	var err error
	g.Negated, g.Items, err = parseEnvList(listStr)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func parseValue(str string, e *entry) error {
	if str, ok := strings.CutPrefix(str, "enc:"); ok {
		e.Encoding = ToBeEncrypted
		keyName, str, ok := strings.Cut(str, ":")
		if !ok {
			return fmt.Errorf(`missing another colon, expected "enc::<value>" or "enc:<keyname>:<value>"`)
		}
		if keyName != "" && !IsValidKeyName(keyName) {
			return fmt.Errorf(`invalid key name %q in "enc:<keyname>:<value>"`, keyName)
		}
		e.PlainValue = str
		e.KeyName = keyName
	} else if str, ok := strings.CutPrefix(str, "secret:"); ok {
		comps := strings.Split(str, ":")
		if len(comps) != 3 {
			return fmt.Errorf(`invalid secret value, expected "secret:<keyname>:<nonce>:<ciphertext>"`)
		}
		keyName, nonceStr, ciphertextStr := comps[0], comps[1], comps[2]

		if !IsValidKeyName(keyName) {
			return fmt.Errorf(`invalid key name %q in "secret:<keyname>:<nonce>:<ciphertext>"`, keyName)
		}

		nonce, err := base64.StdEncoding.DecodeString(nonceStr)
		if err != nil {
			return fmt.Errorf(`invalid nonce in "secret:<keyname>:<nonce>:<ciphertext>": %w`, err)
		}
		if len(nonce) != NonceSize {
			return fmt.Errorf(`invalid nonce len in "secret:<keyname>:<nonce>:<ciphertext>", got %d, wanted %d`, len(nonce), NonceSize)
		}

		ciphertext, err := base64.StdEncoding.DecodeString(ciphertextStr)
		if err != nil {
			return fmt.Errorf(`invalid cihertext in "secret:<keyname>:<nonce>:<ciphertext>": %w`, err)
		}

		e.Encoding = Encrypted
		e.KeyName = keyName
		copy(e.Nonce[:], nonce)
		e.Ciphertext = ciphertext
	} else if str, ok := strings.CutPrefix(str, "TODO:"); ok {
		e.Encoding = Placeholder
		e.PlainValue = str
	} else if str == "TODO" {
		e.Encoding = Placeholder
	} else if str == "NONE" || str == "none" {
		e.Encoding = NoValue
	} else {
		e.Encoding = Plain
		e.PlainValue = str
	}
	return nil
}
