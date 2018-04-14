PROG=		filecrypt
SRCS=		main.c

LDADD=		-lcrypto -lutil
DPADD=		${LIBCRYPTO} ${LIBUTIL}

CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-qual

BINDIR=		/usr/local/bin
NOMAN=		noman

secret=		secret.passphrase
testsize=	bs=$$(($$RANDOM % 512 + 1)) count=$$(($$RANDOM % 8192 + 1024))

test: ${PROG}
	dd if=/dev/random of=foo.bin ${testsize}
	sha256 -h SHA256 foo.bin
	tr -cd [:graph:] < /dev/random | fold -bw 40 | head -1 > ${secret}
	${.OBJDIR}/${PROG} -k ${secret} < foo.bin > bar.bin
	${.OBJDIR}/${PROG} -d -k ${secret} < bar.bin > foo.bin
	sha256 -c SHA256

.include <bsd.prog.mk>
