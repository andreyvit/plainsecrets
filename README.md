plainsecrets: Encrypted plaintext secrets in Go apps
====================================================

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/plainsecrets.svg)](https://pkg.go.dev/github.com/andreyvit/plainsecrets) ![only dependency is golang.org/x/crypto](https://img.shields.io/badge/only%20dependency-golang.org%2Fx%2Fcrypto-green) ![50% coverage](https://img.shields.io/badge/coverage-50%25-yellow) [![Go Report Card](https://goreportcard.com/badge/github.com/andreyvit/plainsecrets)](https://goreportcard.com/report/github.com/andreyvit/plainsecrets)

Uses NaCl-compatible secretbox encryption (XSalsa20 + Poly1305) via [golang.org/x/crypto/nacl/secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox).


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
@all = prod staging localdev
@localdev = local-*
@nonprod = ! prod

THREADS.prod = 10
THREADS.localdev = 5
THREADS.local-john = 4

ACME_KEY.nonprod=secret:myapp-dev:A3lTDIMkbrUK92o71D8lhcpFN1SqfPYw:hKOYGyNQ8nAZ8caTD4Zng4EXDPZ61rlpzTjY
ACME_KEY.prod=secret:myapp-prod:aHyVs0drNzWPnMC6t1ZZxuwg+k1HwV3o:+rle6B2otsa9gXvJ5yr/CaV+1w==
````

To encrypt a new secret, first add to `secrets.txt`:

```ini
ROOT_PW=enc::shortpassword
ROOT_PW.prod=enc::longpassword
```

and configure `DEFAULT_KEY`:

```ini
DEFAULT_KEY = myapp-dev
DEFAULT_KEY.prod = myapp-prod
```

then invoke:

```sh
plainsecrets -K .keyring -f secrets.txt
```

(or just use LoadFileValues with last argument set to `true`, which will automatically encrypt new entries).

This results in:

```ini
ROOT_PW=secret:myapp-dev:bVsQKDhuMTMQVNnjjLPVHEnlMygh6M3O:Lg9L0jwxomhyqXPHGomZLg5O2KUZsRt240esWXM=
ROOT_PW.prod=secret:myapp-prod:ZrABQcMmHwMjIKeVBhKt9vsQsFxEVstr:tNKmgPptQjSDwWaBNidW0Q0+R+rIMuElyCKrAQ==
````

To decrypt secrets from command line:

```sh
plainsecrets -K .keyring -f secrets.txt '*'
plainsecrets -K .keyring -f secrets.txt 'OPENAI_*'
plainsecrets -K .keyring -f secrets.txt 'OPENAI_CLIENT_SECRET'
```

To load secrets from code:

```go
keyring := must(plainsecrets.ParseKeyringFile(".keyring"))

values := must(plainsecrets.LoadFileValues("secrets.txt", env, keyring))
for k, v := range values {
    log.Printf("\t%s = %s", k, v)
}
```


Keyring File Format
-------------------

```ini
myapp-prod=rTYS3+vPf0XfCPW4tCykpQoqcxMyiciNLaDlj+VSuQU=
myapp-dev=5OnO+jqOo/hhz1DVJox3TpaefmbwFqbiw6HYfuogz+Y=
```


Secrets File Format
-------------------

Secrets and settings are adjustable per environment. Define environments in the file:

1. Define groups of environments via `@group = env1 group2 env3...`. Groups can include other groups.
2. You can use `*` wildcard in group definitions, e.g. `@local = local-*`. This group will include `local-john`, `local-bob`, etc.
3. You MUST define all possible environments as group `all`, e.g. `@all = prod stag dev local-*`. Use `*` to allow any environment names: `@all = *`.
4. Setting or querying values for environments outside of `@all` will return an error. This is meant to protect from typos in configurations going unnoticed.

Then define values of secrets:

1. Use `SECRET_NAME.env = VALUE` syntax. Omitting `.env` (`SECRET_NAME = VALUE`) is the same as saying `.all`. Env can be either a specific environment or a group defined above.
2. You can set different values for different environments. A value MUST be set for EVERY environment in `@all`. This is to ensure that if the app has sufficient secrets in dev, it will also have sufficient secrets in production. Secrets file will refuse to load otherwise.
3. Use `SECRET_NAME.env = NONE` to explicitly indicate that no value is provided for the given environment. In this case, querying the secret in the given environment will return an empty string with no error.
4. Use `SECRET_NAME.env = TODO` or `SECRET_NAME.env = TODO: comment` to indicate that a value will be provided later. Querying the secret in the given environment will return an error. This is meant to be used in example files.
5. Use `SECRET_NAME.env = enc:<keyname>:<value>` to indicate that plaintext value should be encrypted with the given key, and replaced with encrypted one.
6. Use `SECRET_NAME.env = enc::<value>` to auto-select the key based on the environment and `DEFAULT_KEY` setting.
7. Use `SECRET_NAME.env = secret:<keyname>:<nonce>:<ciphertext>` for encrypted secrets. Use `enc::...` or `enc:<keyname>:...` values to produce these.
8. The order of values does not matter. In case multiple rows apply to a given environment (say, `FOO.nonprod` and `FOO.local` both match `local-john`):
    - longer wildcards win over shorter wildcards (e.g. a group that included local-john wins over a group matching `local-*`);
    - for matches of same length, narrower groups win over broader groups (e.g. single environment name wins over a group matching 2 environments, which wins over a group matching 3 environments);
    - if the match length and group size is the same, it is an error for multiple groups to match.

Example:

```ini
# This file starts with environment group definitions:
#
#     @group1 = env1 env2 group2 env4 ...
#
# followed by a bunch of secrets:
#
#     NAME1 = value1
#     NAME2 = value2
#
# which can be customized per env or env group:
#
#     NAME1.env1 = value3
#     NAME1.group2 = value4
#
# The order of declarations doesn't matter. Values set for
# narower groups win over values set for broader groups.
# Setting conflicting values for equal-sized groups is an error.

# @all is required and declares valid environments, use * to allow any,
# can include subgroups.
@all = prod staging local
@staging = stag dev branches
@local = local-*
@branches = b-*

# use ! to negate entire list
@nonprod = ! prod
@devstag = dev stag
@nonjohn = ! local-john

DEFAULT_KEY.prod = myapp-prod
DEFAULT_KEY = myapp-dev

FOO.local-john = 1
FOO.local = 2
FOO.nonprod = 3
FOO.prod = 4

ACME_CLIENT_KEY=secret:myapp-dev:A3lTDIMkbrUK92o71D8lhcpFN1SqfPYw:hKOYGyNQ8nAZ8caTD4Zng4EXDPZ61rlpzTjY
ACME_CLIENT_KEY.prod=secret:myapp-prod:aHyVs0drNzWPnMC6t1ZZxuwg+k1HwV3o:+rle6B2otsa9gXvJ5yr/CaV+1w==

````



Contributing
------------

Contributions are welcome, but keep in mind that I want to keep this library focused.

Auto-testing via modd (`go install github.com/cortesi/modd/cmd/modd@latest`):

    modd


MIT license
-----------

Copyright (c) 2023 Andrey Tarantsov. Published under the terms of the [MIT license](LICENSE).
