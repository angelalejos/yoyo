/*
 * Copyright (c) 2017, 2018 Steven Roberts <sroberts@fenderq.com>
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
#include <limits.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#define BUFSIZE (1024 * 1024)
#define DEFAULT_CIPHER "chacha"
#define PASSWD_MAX 128
#define PASSWD_MIN 8
#define ROUNDS 128
#define SALT_SIZE 16

struct cipher_info {
	FILE *fin;
	FILE *fout;
	char keyfile[PATH_MAX];
	const EVP_CIPHER *cipher;
	const char *cipher_name;
	int enc;
	int iv_len;
	int key_len;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char salt[SALT_SIZE];
};

extern char *optarg;

__dead void	 usage(void);

void		 crypto_error(void);
int		 crypto_stream(struct cipher_info *);
int		 filecrypt(struct cipher_info *);
int		 kdf(struct cipher_info *);
int 		 passwd_read_file(char *, size_t, char *);
int 		 passwd_read_tty(char *, size_t, int);

int
main(int argc, char *argv[])
{
	char ch;
	struct cipher_info *c;

	if (pledge("rpath stdio tty", NULL) == -1)
		err(1, "pledge");

	if ((c = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);

	c->enc = 1;
	c->fin = stdin;
	c->fout = stdout;

	while ((ch = getopt(argc, argv, "dk:")) != -1) {
		switch (ch) {
		case 'd':
			c->enc = 0;
			break;
		case 'k':
			strlcpy(c->keyfile, optarg, sizeof(c->keyfile));
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	filecrypt(c);

	freezero(c, sizeof(struct cipher_info));

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-d] [-k keyfile]\n", getprogname());
	exit(EXIT_FAILURE);
}

void
crypto_error(void)
{
	unsigned long error;

	error = ERR_get_error();
	errx(1, "%s", ERR_error_string(error, NULL));
}

int
crypto_stream(struct cipher_info *c)
{
	EVP_CIPHER_CTX *ctx;
	int done;
	int inl;
	int outl;
	int wlen;
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

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		crypto_error();

	if (EVP_CipherInit_ex(ctx, c->cipher, NULL,
	    c->key, c->iv, c->enc) != 1)
		crypto_error();

	do {
		if ((n = fread(in, 1, inl, c->fin)) != 0) {
			if (EVP_CipherUpdate(ctx, out, &wlen, in, n) != 1)
				crypto_error();
		} else {
			if (ferror(c->fin) != 0)
				errx(1, "error reading stream");
			if (EVP_CipherFinal_ex(ctx, out, &wlen) != 1)
				crypto_error();
			done = 1;
		}
		if (fwrite(out, wlen, 1, c->fout) != 1)
			errx(1, "error writing stream");
	} while (!done);

	EVP_CIPHER_CTX_free(ctx);

	freezero(out, outl);
	freezero(in, inl);

	return 0;
}

int
filecrypt(struct cipher_info *c)
{
	ERR_load_crypto_strings();

	c->cipher_name = DEFAULT_CIPHER;
	if ((c->cipher = EVP_get_cipherbyname(c->cipher_name)) == NULL)
		errx(1, "invalid cipher %s", c->cipher_name);

	c->iv_len = EVP_CIPHER_iv_length(c->cipher);
	c->key_len = EVP_CIPHER_key_length(c->cipher);

	if (c->enc) {
		arc4random_buf(c->salt, sizeof(c->salt));
		arc4random_buf(c->iv, sizeof(c->iv));
		if (fwrite(c->salt, sizeof(c->salt), 1, c->fout) != 1)
			errx(1, "error writing salt");
		if (fwrite(c->iv, sizeof(c->iv), 1, c->fout) != 1)
			errx(1, "error writing iv");
	} else {
		if (fread(c->salt, sizeof(c->salt), 1, c->fin) != 1)
			errx(1, "error reading salt");
		if (fread(c->iv, sizeof(c->iv), 1, c->fin) != 1)
			errx(1, "error reading iv");
	}

	kdf(c);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	crypto_stream(c);

	ERR_free_strings();

	return 0;
}

int
kdf(struct cipher_info *c)
{
	char passwd[PASSWD_MAX];

	if (c->keyfile[0] != '\0')
		passwd_read_file(passwd, sizeof(passwd), c->keyfile);
	else
		passwd_read_tty(passwd, sizeof(passwd), c->enc);

	if (bcrypt_pbkdf(passwd, strlen(passwd), c->salt, sizeof(c->salt),
	    c->key, c->key_len, ROUNDS) == -1)
		errx(1, "bcrypt_pbkdf failure");

	explicit_bzero(passwd, sizeof(passwd));

	return 0;
}

int
passwd_read_file(char *pass, size_t size, char *fname)
{
	FILE *fp;
	char *line;
	int linecount;
	size_t linesize;
	size_t passlen;
	ssize_t linelen;

	if ((fp = fopen(fname, "r")) == NULL)
		err(1, "%s", fname);

	linesize = LINE_MAX;
	if ((line = malloc(linesize)) == NULL)
		err(1, NULL);

	linecount = 0;
	memset(pass, 0, size);

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		line[strcspn(line, "\n")] = '\0';
		strlcpy(pass, line, size);
		linecount++;
	}
	if (ferror(fp) != 0)
		errx(1, "error reading file %s", fname);

	if (linecount > 1)
		errx(1, "%s contains multiple lines (%d)", fname, linecount);

	passlen = strlen(pass);

	if (passlen == 0)
		errx(1, "please provide a password");

	if (passlen < PASSWD_MIN)
		errx(1, "password too small");

	freezero(line, linesize);

	if (ferror(fp))
		err(1, "%s", fname);

	fclose(fp);

	return 0;
}

int
passwd_read_tty(char *pass, size_t size, int confirm)
{
	char pass2[PASSWD_MAX];
	int flags;
	size_t passlen;

	flags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;

	if (!readpassphrase("passphrase: ", pass, size, flags))
		errx(1, "unable to read passphrase");

	passlen = strlen(pass);

	if (passlen == 0)
		errx(1, "please provide a password");

	if (confirm) {
		if (passlen < PASSWD_MIN)
			errx(1, "password too small");
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), flags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		explicit_bzero(pass2, sizeof(pass2));
	}

	return 0;
}
