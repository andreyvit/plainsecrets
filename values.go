package plainsecrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize    = 32
	NonceSize  = 24
	All        = "all"
	DefaultKey = "DEFAULT_KEY"
)

type Values struct {
	envs         map[string]*envGroup
	entries      map[string][]*entry
	resolvedEnvs map[string]*resolvedEnvGroup
	validEnvs    []string
	knownEnvs    []string
}

func New() *Values {
	return &Values{
		envs:         make(map[string]*envGroup),
		resolvedEnvs: make(map[string]*resolvedEnvGroup),
		entries:      make(map[string][]*entry),
	}
}

func LoadFileValues(path, env string, keyring Keyring) (map[string]string, error) {
	vals, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	return vals.EnvValues(env, keyring)
}

func LoadStringValues(data, env string, keyring Keyring) (map[string]string, error) {
	vals, err := ParseString(data)
	if err != nil {
		return nil, err
	}
	return vals.EnvValues(env, keyring)
}

func LoadMapValues(data map[string]string, env string, keyring Keyring) (map[string]string, error) {
	vals := New()
	err := vals.ParseMap(data)
	if err != nil {
		return nil, err
	}
	return vals.EnvValues(env, keyring)
}

func (vals *Values) String() string {
	var buf strings.Builder
	for name, es := range vals.envs {
		buf.WriteByte('@')
		buf.WriteString(name)
		buf.WriteString(" = ")
		buf.WriteString(es.String())
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	return buf.String()
}

func (vals *Values) lookupEnv(env string) (*resolvedEnvGroup, bool) {
	result := vals.resolvedEnvs[env]
	if result != nil {
		return result, false
	}

	result = &resolvedEnvGroup{
		state:    mentionedState,
		wildcard: IsWildcard(env),
	}
	vals.resolvedEnvs[env] = result

	if vals.envs[env] == nil {
		if vals.validEnvs == nil {
			_, err := path.Match(env, "")
			if err != nil {
				result.state = resolvedState
				result.err = fmt.Errorf("invalid env wildcard %s", env)
			}
		} else if findMatch(vals.validEnvs, env) == "" {
			result.state = resolvedState
			result.err = fmt.Errorf("env %s is not among @all", env)
		}
	}
	return result, true
}

func (vals *Values) mentionEnv(env string) (bool, error) {
	res, isNew := vals.lookupEnv(env)
	return isNew, res.err
}

func (vals *Values) resolveEnv(env string) (*resolvedEnvGroup, error) {
	result, _ := vals.lookupEnv(env)
	if result.state != resolvedState {
		if result.state == resolvingState {
			return nil, fmt.Errorf("@%s: infinite recursion", env)
		}
		result.state = resolvingState

		definition := vals.envs[env]
		if definition == nil {
			result.included = []string{env}
		} else if definition.Negated {
			if vals.validEnvs == nil {
				return nil, fmt.Errorf("cannot refer to negated groups like %s from @all", env)
			}

			var excluded []string
			for _, subenv := range definition.Items {
				subres, err := vals.resolveEnv(subenv)
				if err != nil {
					return nil, fmt.Errorf("@%s: %w", env, err)
				}
				for _, env := range subres.included {
					if !contains(excluded, env) {
						excluded = append(excluded, env)
					}
				}
			}

			for _, env := range vals.validEnvs {
				if findMatch(excluded, env) == "" {
					result.included = append(result.included, env)
				}
			}
		} else {
			for _, subenv := range definition.Items {
				subres, err := vals.resolveEnv(subenv)
				if err != nil {
					return nil, fmt.Errorf("@%s: %w", env, err)
				}
				for _, env := range subres.included {
					if !contains(result.included, env) {
						result.included = append(result.included, env)
					}
				}
			}
		}
		result.finalize()
		result.state = resolvedState
	}
	return result, result.err
}

type entry struct {
	Env      string
	Resolved *resolvedEnvGroup

	RawLHS string
	RawRHS string

	Encoding   Encoding
	KeyName    string
	Nonce      [NonceSize]byte
	Ciphertext []byte
	PlainValue string
}

func (e *entry) String(name string) string {
	var buf strings.Builder
	if e.Env != "" {
		buf.WriteByte('@')
		buf.WriteString(e.Env)
		buf.WriteByte('.')
	}
	buf.WriteString(name)
	buf.WriteByte('=')
	switch e.Encoding {
	case NoValue:
		buf.WriteString("NONE")
	case Plain:
		buf.WriteString(e.PlainValue)
	case ToBeEncrypted:
		buf.WriteString("enc:")
		buf.WriteString(e.PlainValue)
	case Placeholder:
		buf.WriteString("TODO")
		if e.PlainValue != "" {
			buf.WriteByte(':')
			buf.WriteString(e.PlainValue)
		}
	case Encrypted:
		buf.WriteString("secret:")
		buf.WriteString(e.KeyName)
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(e.Nonce[:]))
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(e.Ciphertext))
	}
	return buf.String()
}

func (e *entry) Value(keyring Keyring) (string, error) {
	switch e.Encoding {
	case NoValue:
		return "", nil
	case Plain, ToBeEncrypted:
		return e.PlainValue, nil
	case Placeholder:
		return "", fmt.Errorf("forgot to specify")
	case Encrypted:
		key := keyring.ByName(e.KeyName)
		if key == nil {
			return "", fmt.Errorf("missing key %s", e.KeyName)
		}
		plaintext, ok := secretbox.Open(nil, e.Ciphertext, &e.Nonce, &key.Data)
		if !ok {
			return "", fmt.Errorf("decryption failed")
		}
		return string(plaintext), nil
	default:
		panic("unreachable")
	}
}

type Encoding int

const (
	NoValue = Encoding(iota)
	Plain
	Placeholder
	Encrypted
	ToBeEncrypted
)

func (vals *Values) rebuild() error {
	vals.validEnvs = nil
	vals.knownEnvs = nil
	for _, res := range vals.resolvedEnvs {
		if res.err == nil {
			res.state = mentionedState
		}
	}

	if vals.envs[All] == nil {
		return fmt.Errorf("missing @%s=...", All)
	}
	if valid, err := vals.resolveEnv(All); err != nil {
		return err
	} else {
		vals.validEnvs = valid.included
	}

	for name, definition := range vals.envs {
		vals.mentionEnv(name)
		for _, subname := range definition.Items {
			vals.mentionEnv(subname)
		}
	}
	for _, ee := range vals.entries {
		for _, e := range ee {
			vals.mentionEnv(e.Env)
		}
	}
	for _, env := range vals.validEnvs {
		if !IsWildcard(env) {
			vals.knownEnvs = append(vals.knownEnvs, env)
		} else {
			for candidate, res := range vals.resolvedEnvs {
				if !res.wildcard && matches(env, candidate) {
					vals.knownEnvs = append(vals.knownEnvs, candidate)
				}
			}
		}
	}

	for env := range vals.envs {
		_, err := vals.resolveEnv(env)
		if err != nil {
			return err
		}
	}

	for name, entries := range vals.entries {
		for _, e := range entries {
			res, err := vals.resolveEnv(e.Env)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			e.Resolved = res
		}
		for _, env := range vals.validEnvs {
			sampleEnv := strings.ReplaceAll(env, "*", "xxx")
			e, err := vals.pickVariant(name, sampleEnv, entries)
			if err != nil {
				return err
			} else if e == nil {
				return fmt.Errorf("no value for %s.%s", name, env)
			}
		}
	}

	// log.Printf("after rebuild:")
	// log.Printf("  envs = %v", vals.envs)
	// log.Printf("  resolvedEnvs = %v", vals.resolvedEnvs)
	// for name, ee := range vals.entries {
	// 	for _, e := range ee {
	// 		log.Printf("  %s.%s [%v] = <%d> %s", name, e.Env, e.Resolved, e.Encoding, e.RawRHS)
	// 	}
	// }

	return nil
}

func (vals *Values) pickVariant(name, env string, entries []*entry) (*entry, error) {

	envRes, err := vals.resolveEnv(env)
	if err != nil {
		return nil, err
	}

	// log.Printf("pickVariant(%s, %s [%v] [%q])", name, env, envRes, envRes.trivial)

	var best *entry
	var bestScore int
	var conflict *entry
	for _, e := range entries {
		var score int
		if envRes.trivial != "" {
			score = e.Resolved.Match(envRes.trivial)
		} else {
			if e.Resolved.Includes(envRes) {
				score = 1
			}
		}
		// if score != 0 {
		// 	log.Printf("pickVariant(%s.%s) for .%s = %d", name, env, e.Env, score)
		// }
		if score > bestScore {
			best, bestScore, conflict = e, score, nil
		} else if best != nil && score == bestScore {
			cmp := e.Resolved.CompareSpecificity(best.Resolved)
			// log.Printf("(%s) <=> (%s) = %d", res.String(), best.Resolved.String(), cmp)
			if cmp > 0 {
				best, bestScore, conflict = e, score, nil
			} else if cmp == 0 {
				conflict = e
			}
		}
	}
	if conflict == nil {
		return best, nil
	} else {
		if best.Env > conflict.Env {
			best, conflict = conflict, best // ensure error msgs are stable
		}
		return best, fmt.Errorf("conflicting values with match length %d for %s.%s and %s.%s when resolving for .%s", bestScore, name, best.Env, name, conflict.Env, env)
	}
}

func (vals *Values) Value(name string, env string, keyring Keyring) (string, error) {
	isNew, err := vals.mentionEnv(env)
	if err != nil {
		return "", err
	}
	if isNew {
		vals.rebuild()
	}

	entries := vals.entries[name]
	if entries == nil {
		return "", nil
	}

	e, err := vals.pickVariant(name, env, entries)
	if err != nil {
		return "", err
	}
	if e == nil {
		return "", fmt.Errorf("no value for %s.%s", name, env)
	}

	val, err := e.Value(keyring)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return val, nil
}

type Variant struct {
	Name    string
	Env     string
	RawLHS  string
	RawRHS  string
	KeyName string
	Value   string
	Err     error
}

func (v *Variant) Raw() string {
	return v.RawLHS + "=" + v.RawRHS
}

func (vals *Values) VariantsToEncrypt() []*Variant {
	var result []*Variant
	for name, vars := range vals.entries {
		for _, e := range vars {
			if e.Encoding == ToBeEncrypted {
				result = append(result, &Variant{name, e.Env, e.RawLHS, e.RawRHS, e.KeyName, e.PlainValue, nil})
			}
		}
	}
	return result
}

func (vals *Values) ValueVariants(name string, keyring Keyring) []*Variant {
	entries := vals.entries[name]
	if entries == nil {
		return nil
	}

	result := make([]*Variant, 0, len(entries))
	for _, e := range entries {
		val, err := e.Value(keyring)
		result = append(result, &Variant{name, e.Env, e.RawLHS, e.RawRHS, e.KeyName, val, err})
	}
	return result
}

func (vals *Values) Names() []string {
	var names []string
	for name := range vals.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (vals *Values) EnvValues(env string, keyring Keyring) (map[string]string, error) {
	result := make(map[string]string, len(vals.entries))
	var lastErr error
	for _, name := range vals.Names() {
		val, err := vals.Value(name, env, keyring)
		if err != nil {
			lastErr = err
		} else if val != "" {
			result[name] = val
		}
	}
	return result, lastErr
}

func (vals *Values) EncryptValue(val string, env string, keyName string, keyring Keyring) (string, error) {
	var keyNameDerived bool
	if keyName == "" {
		if env == "" {
			return "", fmt.Errorf("either env or key name must be specified")
		}
		var err error
		keyName, err = vals.Value(DefaultKey, env, nil)
		if err != nil {
			return "", err
		}
		if keyName == "" {
			return "", fmt.Errorf("%s is empty for env %s", DefaultKey, env)
		}
		keyNameDerived = true
	}

	key := keyring.ByName(keyName)
	if key == nil {
		if keyNameDerived {
			return "", fmt.Errorf("no key %s (via %s)", keyName, DefaultKey)
		} else {
			return "", fmt.Errorf("no key %s", keyName)
		}
	}

	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate none: %w", err)
	}

	ciphertext := secretbox.Seal(nil, []byte(val), &nonce, &key.Data)

	return fmt.Sprintf("secret:%s:%s:%s", keyName, base64.StdEncoding.EncodeToString(nonce[:]), base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (vals *Values) EncryptAllInMap(keyring Keyring) (map[string]string, []*Variant) {
	vars := vals.VariantsToEncrypt()
	if len(vars) == 0 {
		return nil, nil
	}
	result := make(map[string]string)
	var failed []*Variant
	for _, v := range vars {
		rhs, err := vals.EncryptValue(v.Value, v.Env, v.KeyName, keyring)
		if err != nil {
			v.Err = err
			failed = append(failed, v)
		} else {
			result[v.RawLHS] = rhs
		}
	}
	return result, failed
}

func (vals *Values) EncryptAllInString(data string, keyring Keyring) (string, int, []*Variant) {
	vars := vals.VariantsToEncrypt()
	if len(vars) == 0 {
		return data, 0, nil
	}

	var regexps []*regexp.Regexp
	var replacements []string
	var failed []*Variant

	for _, v := range vars {
		rhs, err := vals.EncryptValue(v.Value, v.Env, v.KeyName, keyring)
		if err != nil {
			v.Err = err
			failed = append(failed, v)
			continue
		}

		lhs := regexp.QuoteMeta(v.RawLHS)
		oldRHS := regexp.QuoteMeta(v.RawRHS)
		pat := regexp.MustCompile(`^(\s*` + lhs + `\s*=\s*)` + oldRHS + `\s*$`)
		regexps = append(regexps, pat)
		replacements = append(replacements, rhs)
	}

	lines := strings.Split(data, "\n")
	var modified int
	for li, line := range lines {
		for ri, re := range regexps {
			m := re.FindStringSubmatch(line)
			if m != nil {
				lines[li] = m[1] + replacements[ri]
				modified++
				break
			}
		}
	}
	return strings.Join(lines, "\n"), modified, failed
}

func (vals *Values) EncryptAllInFile(path string, keyring Keyring) (int, []*Variant, error) {
	s, err := os.Stat(path)
	if err != nil {
		return 0, nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}

	newData, modified, failed := vals.EncryptAllInString(string(raw), keyring)
	if modified > 0 {
		err := os.WriteFile(path, []byte(newData), s.Mode())
		return modified, failed, err
	} else {
		return 0, failed, nil
	}
}
