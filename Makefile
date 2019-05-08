.PHONY: all clean test

SANDBOX?=null

all:
	$(CC) -DSANDBOX_$(SANDBOX) \
    -Wall -Wextra -pedantic \
		-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
		-Wformat -Werror=format-security \
		-pie -fPIE \
    -Wshadow -Wpointer-arith -Wcast-qual \
    -Wstrict-prototypes -Wmissing-prototypes \
    -I. \
    -o totp hmac/hmac_sha1.c sha/sha1.c totp.c \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack

clean:
	-@rm totp
