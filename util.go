package secrets

import (
	"fmt"
	"path"
	"strings"
)

func parseMultilineKVString(data string) (map[string]string, error) {
	lines := strings.Split(data, "\n")
	result := make(map[string]string, len(lines))
	for lno, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing =", lno+1)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("line %d: missing key", lno+1)
		}

		if _, dup := result[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate value for %s", lno+1, key)
		}
		result[key] = value
	}

	return result, nil
}

func matches(pattern, candidate string) bool {
	matched, _ := path.Match(pattern, candidate)
	return matched
}

func findMatch(patterns []string, candidate string) string {
	for _, pat := range patterns {
		if matches(pat, candidate) {
			return pat
		}
	}
	return ""
}

func contains(list []string, candidate string) bool {
	for _, item := range list {
		if item == candidate {
			return true
		}
	}
	return false
}
