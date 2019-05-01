.PHONY: all clean test

all:
	$(CC) \
    -Wall -Wextra -pedantic \
		-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
		-Wformat -Werror=format-security \
		-pie -fPIE \
    -Wshadow -Wpointer-arith -Wcast-qual \
    -Wstrict-prototypes -Wmissing-prototypes \
    -o totp totp.c \
		-lcrypto \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack

clean:
	-@rm totp
