package plainsecrets

import (
	_ "embed"
	"testing"
)

//go:embed testdata/keyring.txt
var sampleKeyring string

func TestParseKeyringString(t *testing.T) {
	keyring, err := ParseKeyringString(sampleKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if a, e := keyring.String(), "(myapp-dev, myapp-prod)"; a != e {
		t.Errorf("** keyring.String() = %v, wanted %v", a, e)
	}
}
