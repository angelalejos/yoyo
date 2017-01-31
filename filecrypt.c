/*
 * Copyright (c) 2017 Steven Roberts <sroberts@fenderq.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <unistd.h>
#include <util.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFSIZE 1024 * 1024
#define DEFAULT_CIPHER "aes-128-cbc"
#define MAX_LINE 4096
#define ROUNDS 64
#define SALT_SIZE 16

struct cipher_info {
	FILE *fin;
	FILE *fout;
	const EVP_CIPHER *cipher;
	const char *cipher_name;
	int enc;
	int iv_len;
	int key_len;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];
};

extern char *__progname;
extern char *optarg;

int verbose;

__dead void usage(void);

static int	 crypto_deinit(void);
static void	 crypto_error(void);
static int	 crypto_init(void);
static int	 crypto_stream(struct cipher_info *);
static int	 filecrypt(char *, char *, int);
static void	 kdf(uint8_t *, size_t, int, int, int, uint8_t *, size_t);
static void	 print_value(char *, unsigned char *, int);
static char	*str_hex(char *, int, void *, int);

int
main(int argc, char *argv[])
{
	char ch;
	int dflag;

	dflag = 0;

	crypto_init();

	if (pledge("cpath rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();
	filecrypt(argv[0], argv[1], dflag ? 0 : 1);

	crypto_deinit();

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-dv] infile outfile\n", __progname);
	exit(EXIT_FAILURE);
}

static int
crypto_deinit(void)
{
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}

static void
crypto_error(void)
{
	unsigned long error;

	error = ERR_get_error();
	errx(1, "%s", ERR_error_string(error, NULL));
}

static int
crypto_init(void)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	return 0;
}

static int
crypto_stream(struct cipher_info *ci)
{
	EVP_CIPHER_CTX ctx;
	int done;
	int inl;
	int outl;
	int written;
	size_t n;
	unsigned char *in;
	unsigned char *out;

	done = 0;

	inl = BUFSIZE;
	if ((in = malloc(inl)) == NULL)
		err(1, NULL);

	outl = inl + EVP_MAX_BLOCK_LENGTH;
	if ((out = malloc(outl)) == NULL)
		err(1, NULL);

	EVP_CIPHER_CTX_init(&ctx);
	if (EVP_CipherInit_ex(&ctx, ci->cipher, NULL,
	    ci->key, ci->iv, ci->enc) != 1)
		crypto_error();

	do {
		if ((n = fread(in, 1, inl, ci->fin)) != 0) {
			if (EVP_CipherUpdate(&ctx, out, &written, in, n) != 1)
				crypto_error();
		} else {
			if (ferror(ci->fin) != 0)
				errx(1, "error reading from input stream");
			if (EVP_CipherFinal_ex(&ctx, out, &written) != 1)
				crypto_error();
			done = 1;
		}
		n = written;
		if (fwrite(out, 1, n, ci->fout) != n)
			errx(1, "failure writing to output stream");
	} while (!done);

	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1)
		crypto_error();
	free(out);
	free(in);

	return 0;
}

static int
filecrypt(char *infile, char *outfile, int enc)
{
	int blocksize;
	int rounds;
	struct cipher_info *c;
	unsigned char salt[SALT_SIZE];

	if ((c = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);
	c->cipher_name = DEFAULT_CIPHER;
	c->enc = enc;
	rounds = ROUNDS;

	if ((c->cipher = EVP_get_cipherbyname(c->cipher_name)) == NULL)
		errx(1, "invalid cipher %s", c->cipher_name);
	c->iv_len = EVP_CIPHER_iv_length(c->cipher);
	c->key_len = EVP_CIPHER_key_length(c->cipher);
	blocksize = EVP_CIPHER_block_size(c->cipher);

	if (verbose) {
		printf("cipher: %s\nkey: %dbit\niv: %dbit\nsalt: %ldbit\n"
		    "blocksize: %dbit\nrounds: %d\n", c->cipher_name,
		    c->key_len * 8, c->iv_len * 8, sizeof(salt) * 8,
		    blocksize * 8, rounds);
	}

	if ((c->fin = fopen(infile, "r")) == NULL)
		err(1, "%s", infile);
	if ((c->fout = fopen(outfile, "w")) == NULL)
		err(1, "%s", outfile);

	if (c->enc) {
		RAND_bytes(salt, sizeof(salt));
		RAND_bytes(c->iv, c->iv_len);
		if (fwrite(salt, sizeof(salt), 1, c->fout) != 1)
			errx(1, "error writing salt to %s", infile);
		if (fwrite(c->iv, c->iv_len, 1, c->fout) != 1)
			errx(1, "error writing iv to %s", infile);
	} else {
		if (fread(salt, sizeof(salt), 1, c->fin) != 1)
			errx(1, "error reading salt from %s", infile);
		if (fread(c->iv, c->iv_len, 1, c->fin) != 1)
			errx(1, "error reading iv from %s", infile);
	}

	kdf(salt, sizeof(salt), rounds, 1, c->enc ? 1 : 0, c->key, c->key_len);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if (verbose) {
		print_value("salt", salt, sizeof(salt));
		print_value("key", c->key, c->key_len);
		print_value("iv", c->iv, c->iv_len);
	}

	crypto_stream(c);
	fclose(c->fin);
	fclose(c->fout);
	explicit_bzero(c, sizeof(struct cipher_info));
	ERR_print_errors_fp(stderr);
	free(c);

	return 0;
}

static void
kdf(uint8_t *salt, size_t saltlen, int rounds, int allowstdin, int confirm,
    uint8_t *key, size_t keylen)
{
	char pass[1024];
	int rppflags = RPP_ECHO_OFF;

	if (rounds == 0) {
		memset(key, 0, keylen);
		return;
	}

	if (allowstdin && !isatty(STDIN_FILENO))
		rppflags |= RPP_STDIN;
	if (!readpassphrase("passphrase: ", pass, sizeof(pass), rppflags))
		errx(1, "unable to read passphrase");
	if (strlen(pass) == 0)
		errx(1, "please provide a password");
	if (confirm && !(rppflags & RPP_STDIN)) {
		char pass2[1024];
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), rppflags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		explicit_bzero(pass2, sizeof(pass2));
	}
	if (bcrypt_pbkdf(pass, strlen(pass), salt, saltlen, key,
	    keylen, rounds) == -1)
		errx(1, "bcrypt pbkdf");
	explicit_bzero(pass, sizeof(pass));
}

static void
print_value(char *name, unsigned char *str, int size)
{
	char buf[MAX_LINE];

	str_hex(buf, sizeof(buf), str, size);
	printf("%s = %s\n", name, buf);
	explicit_bzero(buf, sizeof(buf));
}

static char *
str_hex(char *str, int size, void *data, int len)
{
	const int hexsize = 2;
	int i;
	unsigned char *p;

	memset(str, 0, size);
	p = data;
	for (i = 0; i < len; i++) {
		if (size <= hexsize) {
			warnx("string truncation");
			break;
		}
		snprintf(str, size, "%02X", p[i]);
		size -= hexsize;
		str += hexsize;
	}

	return str;
}
