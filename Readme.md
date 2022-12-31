A dns service that can be used to perform DNS rebinding attacks.

The resolved IPs are represented in hexadecimal notation as shown below.

Usage:
```shell
$ dig 1-7F000001.2-7F000002.custom.domain.com
  > #1 resolves to 127.0.0.1
  > #2 resolves to 127.0.0.2
  > #3 resolves to 127.0.0.2
  
$ dig 7F000001.7F000002.custom.domain.com
  > # randomly resolves to 127.0.0.1 or 127.0.0.2
```
