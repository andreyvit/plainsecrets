package secrets

import (
	"strings"
)

type envGroup struct {
	Negated bool
	Items   []string
}

func (ed *envGroup) String() string {
	var buf strings.Builder
	if ed.Negated {
		buf.WriteString("! ")
	}
	for _, env := range ed.Items {
		buf.WriteByte(' ')
		buf.WriteString(env)
	}
	return strings.TrimSpace(buf.String())
}

type resolutionState int

const (
	mentionedState = resolutionState(iota)
	resolvingState
	resolvedState
)

type resolvedEnvGroup struct {
	state    resolutionState
	wildcard bool
	err      error
	included []string
	trivial  string
}

func (res *resolvedEnvGroup) String() string {
	var buf strings.Builder
	for _, env := range res.included {
		buf.WriteString(env)
		buf.WriteByte(' ')
	}
	return strings.TrimSpace(buf.String())
}

func (res *resolvedEnvGroup) finalize() {
	if len(res.included) == 1 && !IsWildcard(res.included[0]) {
		res.trivial = res.included[0]
	} else {
		res.trivial = ""
	}
}

func (a *resolvedEnvGroup) CompareSpecificity(b *resolvedEnvGroup) int {
	ai, bi := len(a.included), len(b.included)
	if ai < bi {
		return 1
	} else if ai > bi {
		return -1
	}
	return 0
}

func (res *resolvedEnvGroup) Match(env string) int {
	return len(res.FindMatch(env))
}

func (res *resolvedEnvGroup) FindMatch(env string) string {
	return findMatch(res.included, env)
}

func (res *resolvedEnvGroup) Includes(peer *resolvedEnvGroup) bool {
	for _, env := range peer.included {
		if res.Match(env) == 0 {
			// log.Printf("[%v].Includes([%v]) = false because !a.Match(%s)", res, peer, env)
			return false
		}
	}
	// log.Printf("[%v].Includes([%v]) = true", res, peer)
	return true
}
