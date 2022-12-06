A dns service that can be used to perform DNS rebinding attacks.

When first called for a specific domain the service returns `1.1.1.1` and
when called a second time it responds with the wanted ip.

Usage:
```shell
$ dig 127-0-0-1.custom.domain.com
  > # resolves to 1.1.1.1
$ dig 127-0-0-1.custom.domain.com
  > # resolves to 127.0.0.1
```