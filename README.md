Encrypted secrets in Go apps
============================

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/secrets.svg)](https://pkg.go.dev/github.com/andreyvit/secrets) ![only dependency is golang.org/x/crypto](https://img.shields.io/badge/only%20dependency-golang.org%2Fx%2Fcrypto-green) ![50% coverage](https://img.shields.io/badge/coverage-50%25-yellow) [![Go Report Card](https://goreportcard.com/badge/github.com/andreyvit/secrets)](https://goreportcard.com/report/github.com/andreyvit/secrets)


Why?
----

TODO


Usage
-----

Install:

    go get github.com/andreyvit/secrets
    go install github.com/andreyvit/secrets/cmd/gosecrets@latest

Use:

```sh
gosecrets -K .keyring -addkey mykey
gosecrets -K .keyring -f secrets.txt -addkey mykey
```

```go
TODO
```


Contributing
------------

TODO



MIT license
-----------

Copyright (c) 2023 Andrey Tarantsov. Published under the terms of the [MIT license](LICENSE).
