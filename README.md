# totp.c: simple, standalone TOTP

totp.c is a small, simple, standalone command line TOTP
([RFC6238](https://tools.ietf.org/html/rfc6238)) without any external
dependencies.

`totp.c` was written by
[David M. Syzdek](https://gist.github.com/syzdek/eba233ca33e1b5a45a99).

The standalone `hmac_sha1` implementation is by
[Bob Liu](https://github.com/Akagi201/hmac-sha1).

## Building

```
# use the default rlimit process restrictions
make

# use the seccomp process restrictions
RESTRICT_PROCESS=seccomp make clean all

# disable the process restrictions
RESTRICT_PROCESS=null make clean all

#### using musl
## sudo apt install musl-dev musl-tools
RESTRICT_PROCESS=rlimit ./musl-make

## linux seccomp process restrictions: requires kernel headers
export MUSL_INCLUDE=/tmp
git clone https://github.com/sabotage-linux/kernel-headers.git $MUSL_INCLUDE/kernel-headers
./musl-make clean all
```

## Usage

```
Usage: totp <b32_key> [ <interval> [ <offset> ] ]

totp YW2N4W7UBAIAEVCT

# 30 second intervals (default)
totp YW2N4W7UBAIAEVCT 30

# previous window
totp YW2N4W7UBAIAEVCT 30 -30

# next window
totp YW2N4W7UBAIAEVCT 30 30

# read key from stdin
echo YW2N4W7UBAIAEVCT | totp - 30
```

## Why?

I needed a simple TOTP application that could be statically linked for
use on an old powerpc linux device.
