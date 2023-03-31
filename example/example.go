package main

import (
	"flag"
	"log"

	"github.com/andreyvit/plainsecrets"
)

func main() {
	log.SetFlags(0)
	var env string
	flag.StringVar(&env, "env", "dev", "environment")
	flag.Parse()

	keyring := must(plainsecrets.ParseKeyringFile("testdata/keyring.txt"))

	values := must(plainsecrets.LoadFileValues("testdata/secrets.txt", env, keyring, true))
	log.Printf("Secrets for env %s:", env)
	for k, v := range values {
		log.Printf("\t%s = %s", k, v)
	}
}

func ensure(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
