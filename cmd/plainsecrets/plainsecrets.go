package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/andreyvit/plainsecrets"
)

func main() {
	log.SetFlags(0)

	var keyringFile string
	var keyringEnv string
	var secretsFile string
	var secretsEnv string
	var addKey string
	var key string
	var env string
	flag.StringVar(&keyringFile, "K", "", "path to keyring file (alternative to -KV)")
	flag.StringVar(&keyringEnv, "KV", "", "env var with path to keyring file (alternative to -K)")
	flag.StringVar(&secretsFile, "f", "", "path to secrets file (alternative to -fv)")
	flag.StringVar(&secretsEnv, "fv", "", "env var with path to secrets file (alternative to -f)")
	flag.StringVar(&addKey, "addkey", "", "generate a key and add to keyring under this name")
	flag.StringVar(&key, "k", "", "use key with this name for encrypting secrets")
	flag.StringVar(&env, "e", "", "environment to get/set for")
	flag.Parse()

	if keyringFile == "" {
		if keyringEnv == "" {
			log.Fatalf("*** either -K or -E must be specified.")
		}
		keyringFile = os.Getenv(keyringEnv)
		if keyringFile == "" {
			log.Fatalf("*** missing environment variable %s.", keyringEnv)
		}
	}

	keyring, err := plainsecrets.ParseKeyringFile(keyringFile)
	if err != nil && os.IsNotExist(err) && addKey != "" {
		err = nil
	}
	if err != nil {
		ensure(fmt.Errorf("cannot read keyring: %w", err))
	}

	if addKey != "" {
		keyring.Add(plainsecrets.NewKey(addKey))
		ensure(os.WriteFile(keyringFile, []byte(keyring.Data()), 0600))
	}

	if secretsFile == "" {
		if secretsEnv == "" {
			if addKey != "" {
				return
			}
			log.Fatalf("*** either -f or -fe must be specified.")
		}
		secretsFile = os.Getenv(secretsEnv)
		if secretsFile == "" {
			log.Fatalf("*** missing environment variable %s.", secretsEnv)
		}
	}

	vals, err := plainsecrets.ParseFile(secretsFile)
	if err != nil && os.IsNotExist(err) {
		err = nil
		vals = plainsecrets.New()
	}
	if err != nil {
		ensure(err)
	}

	if flag.NArg() > 0 {
		patterns := flag.Args()
		for _, pat := range patterns {
			if !plainsecrets.IsValidValueNameWildcard(pat) {
				log.Fatalf("** invalid pattern %q", pat)
			}
		}

		names := vals.Names()
		for _, name := range names {
			var matched bool
			for _, pat := range patterns {
				ok, _ := path.Match(pat, name)
				if ok {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			if env == "" {
				for _, v := range vals.ValueVariants(name, keyring) {
					if v.Err != nil {
						fmt.Printf("# %s.%s -> ** %v\n", name, v.Env, v.Err)
					} else {
						fmt.Printf("%s.%s=%s\n", name, v.Env, v.Value)
					}
				}
			} else {
				val, err := vals.Value(name, env, keyring)
				if err != nil {
					fmt.Printf("# %s -> ** %v\n", name, err)
				} else {
					fmt.Printf("%s=%s\n", name, val)
				}
			}
		}
	} else {
		n, failed, err := vals.EncryptAllInFile(secretsFile, keyring)
		ensure(err)
		for _, v := range failed {
			log.Printf("** cannot encrypt %s: %v", v.Raw(), v.Err)
		}
		if n > 0 {
			log.Printf("%d encrypted.", n)
		} else {
			log.Printf("no changes.")
		}
	}

	// secret:v1:bubblehouse-prod:sdfsdfsdfsd:dsfdsfdsfds
}

func ensure(err error) {
	if err != nil {
		log.Fatalf("*** %v", err)
	}
}
