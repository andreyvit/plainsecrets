plainsecrets: Encrypted plaintext secrets in Go apps
====================================================

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/secrets.svg)](https://pkg.go.dev/github.com/andreyvit/secrets) ![only dependency is golang.org/x/crypto](https://img.shields.io/badge/only%20dependency-golang.org%2Fx%2Fcrypto-green) ![50% coverage](https://img.shields.io/badge/coverage-50%25-yellow) [![Go Report Card](https://goreportcard.com/badge/github.com/andreyvit/secrets)](https://goreportcard.com/report/github.com/andreyvit/secrets)


Why?
----

To store secrets in plaintext files, either go:embed'ed into the binary, or downloaded from a central location like S3.

Why? So that adding a new secret no longer requires reconfiguring servers or pinging the entire team.


Usage
-----

Install:

    go get github.com/andreyvit/plainsecrets
    go install github.com/andreyvit/plainsecrets/cmd/plainsecrets@latest

Generate keys and save to keyring:

```sh
plainsecrets -K .keyring -addkey myapp-dev
plainsecrets -K .keyring -addkey myapp-prod
```

Declare environments and values in `secrets.txt`:

```ini
@all = production staging localdev
@localdev = local-*
@nonprod = ! production

THREADS.production = 10
THREADS.localdev = 5
THREADS.local-john = 4

ACME_KEY.nonprod=secret:myapp-dev:A3lTDIMkbrUK92o71D8lhcpFN1SqfPYw:hKOYGyNQ8nAZ8caTD4Zng4EXDPZ61rlpzTjY
ACME_KEY.prod=secret:myapp-prod:aHyVs0drNzWPnMC6t1ZZxuwg+k1HwV3o:+rle6B2otsa9gXvJ5yr/CaV+1w==
````

To encrypt a new secret, first add to `secrets.txt`:

```ini
ROOT_PW=enc::shortpassword
ROOT_PW.production=enc::longpassword
```

and configure `DEFAULT_KEY`:

```ini
DEFAULT_KEY = myapp-dev
DEFAULT_KEY.production = myapp-prod
```

then invoke:

```sh
plainsecrets -K .keyring -f secrets.txt
```

which results in:

```ini
ROOT_PW=secret:myapp-dev:bVsQKDhuMTMQVNnjjLPVHEnlMygh6M3O:Lg9L0jwxomhyqXPHGomZLg5O2KUZsRt240esWXM=
ROOT_PW.production=secret:myapp-prod:ZrABQcMmHwMjIKeVBhKt9vsQsFxEVstr:tNKmgPptQjSDwWaBNidW0Q0+R+rIMuElyCKrAQ==
````

To decrypt secrets from command line:

```sh
plainsecrets -K .keyring -f secrets.txt '*'
plainsecrets -K .keyring -f secrets.txt 'OPENAI_*'
plainsecrets -K .keyring -f secrets.txt 'OPENAI_CLIENT_SECRET'
```

To load secrets from code:




Contributing
------------

TODO



MIT license
-----------

Copyright (c) 2023 Andrey Tarantsov. Published under the terms of the [MIT license](LICENSE).
