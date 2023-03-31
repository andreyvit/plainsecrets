package secrets

import (
	"crypto/rand"
	"fmt"
	"io"
)

type Key struct {
	Name string
	Data [KeySize]byte
}

// String implements fmt.Stringer without exposing sensitive data.
func (key *Key) String() string {
	return key.Name
}

func NewKey(name string) *Key {
	key := &Key{Name: name}
	_, err := io.ReadFull(rand.Reader, key.Data[:])
	if err != nil {
		panic(fmt.Errorf("failed to generate random key: %w", err))
	}
	return key
}
