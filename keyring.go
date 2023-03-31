package secrets

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Keyring []*Key

func (keyring *Keyring) Add(key *Key) {
	*keyring = append(*keyring, key)
}

func (keyring Keyring) ByName(name string) *Key {
	for _, key := range keyring {
		if key.Name == name {
			return key
		}
	}
	return nil
}

// String implements fmt.Stringer without exposing sensitive data.
func (keyring Keyring) String() string {
	var buf strings.Builder
	buf.WriteString("(")

	sorted := make(Keyring, len(keyring))
	copy(sorted, keyring)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	for i, key := range sorted {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(key.Name)
	}
	buf.WriteString(")")
	return buf.String()
}

func (keyring Keyring) Data() string {
	var buf strings.Builder
	for _, key := range keyring {
		buf.WriteString(key.Name)
		buf.WriteByte('=')
		buf.WriteString(base64.StdEncoding.EncodeToString(key.Data[:]))
		buf.WriteByte('\n')
	}
	return buf.String()
}

func ParseKeyringFile(path string) (Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keyring, err := ParseKeyringString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keyring, nil
}

func ParseKeyringString(data string) (Keyring, error) {
	kv, err := parseMultilineKVString(data)
	if err != nil {
		return nil, err
	}
	return ParseKeyringMap(kv)
}
