PROG=		filecrypt
SRCS=		filecrypt.c

DPADD=		${LIBCRYPTO} ${LIBUTIL}
LDADD=		-lcrypto -lutil

CFLAGS+=	-Wall -Werror -ansi -pedantic
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare

NOMAN=		noman

secret=		secret.passphrase
testsize=	bs=$$(($$RANDOM % 1024 + 1)) count=$$(($$RANDOM % 8192 + 1024))

test: ${PROG}
	dd if=/dev/random of=foo.bin ${testsize}
	sha256 foo.bin | tee SHA256
	tr -cd [:graph:] < /dev/random | fold -bw 20 | head -1 | tee ${secret}
	${PROG} -v foo.bin bar.bin < ${secret}
	${PROG} -v -d bar.bin foo.bin < ${secret}
	sha256 -c SHA256

.include <bsd.prog.mk>
