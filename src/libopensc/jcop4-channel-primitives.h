/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Offline candidate primitives. No APDU, PIN, card I/O or channel lifecycle.
 * CBC decryption/unpadding are NOT authentication: callers must verify the
 * MAC over the correct protected message before using recovered plaintext. */
#ifndef JCOP4_CHANNEL_PRIMITIVES_H
#define JCOP4_CHANNEL_PRIMITIVES_H

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stddef.h>
#include <string.h>

#define JCOP4_SM_CRYPTO_LIMIT 4096

static inline int
jcop4_sm_next_ssc(const unsigned char current[16], unsigned char next[16])
{
	unsigned char candidate[16];
	int i, result = 1;
	if (!current || !next)
		return 1;
	memcpy(candidate, current, sizeof(candidate));
	for (i = 15; i >= 0; i--) {
		if (++candidate[i]) {
			memcpy(next, candidate, sizeof(candidate));
			result = 0;
			break;
		}
	}
	/* Reject overflow without wrapping the caller's counter to zero. */
	OPENSSL_cleanse(candidate, sizeof(candidate));
	return result;
}

static inline int
jcop4_sm_pad(const unsigned char *input, size_t size,
		unsigned char *output, size_t capacity, size_t *written)
{
	size_t padded;
	if (!written)
		return 1;
	*written = 0;
	if ((!input && size) || !output || size >= JCOP4_SM_CRYPTO_LIMIT)
		return 1;
	padded = size + 16 - size % 16;
	if (capacity < padded)
		return 1;
	if (size)
		memmove(output, input, size);
	output[size] = 0x80;
	memset(output + size + 1, 0, padded - size - 1);
	*written = padded;
	return 0;
}

static inline int
jcop4_sm_unpad(const unsigned char *input, size_t size, size_t *plain_size)
{
	size_t end;
	if (!plain_size)
		return 1;
	*plain_size = 0;
	if (!input || !size || size > JCOP4_SM_CRYPTO_LIMIT || size % 16)
		return 1;
	end = size;
	while (end > size - 16 && input[end - 1] == 0)
		end--;
	if (end == size - 16 || input[end - 1] != 0x80)
		return 1;
	*plain_size = end - 1;
	return 0;
}

static inline int
jcop4_sm_aes128_cbc_ex(OSSL_LIB_CTX *libctx, int encrypt, const unsigned char key[16], const unsigned char iv[16],
		const unsigned char *input, size_t size, unsigned char *output, size_t capacity)
{
	unsigned char candidate[JCOP4_SM_CRYPTO_LIMIT + 16] = {0};
	EVP_CIPHER *cipher = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	int part = 0, tail = 0, result = 1;
	if (!key || !iv || !input || !output || !size || size > JCOP4_SM_CRYPTO_LIMIT ||
			size % 16 || capacity < size || (encrypt != 0 && encrypt != 1))
		goto out;
	cipher = EVP_CIPHER_fetch(libctx, "AES-128-CBC", NULL);
	ctx = EVP_CIPHER_CTX_new();
	if (!cipher || !ctx || EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, NULL) != 1 ||
			EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
			EVP_CipherUpdate(ctx, candidate, &part, input, (int)size) != 1 ||
			part < 0 || (size_t)part > size ||
			EVP_CipherFinal_ex(ctx, candidate + part, &tail) != 1 || tail != 0 || (size_t)part != size)
		goto out;
	memcpy(output, candidate, size);
	result = 0;
out:
	/* No partially decrypted output on error; caller buffer stays unchanged. */
	OPENSSL_cleanse(candidate, sizeof(candidate));
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(cipher);
	return result;
}

static inline int
jcop4_sm_cmac_ex(OSSL_LIB_CTX *libctx, const unsigned char key[16], const unsigned char *input,
		size_t size, unsigned char output[16])
{
	unsigned char candidate[16] = {0};
	EVP_MAC *algorithm = NULL;
	EVP_MAC_CTX *ctx = NULL;
	char cipher[] = "AES-128-CBC";
	OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0),
			OSSL_PARAM_construct_end()};
	size_t written = 0;
	int result = 1;
	if (!output)
		return 1;
	if (!key || (!input && size) || size > JCOP4_SM_CRYPTO_LIMIT)
		goto out;
	algorithm = EVP_MAC_fetch(libctx, "CMAC", NULL);
	if (algorithm)
		ctx = EVP_MAC_CTX_new(algorithm);
	if (!ctx || EVP_MAC_init(ctx, key, 16, params) != 1 ||
			(size && EVP_MAC_update(ctx, input, size) != 1) ||
			EVP_MAC_final(ctx, candidate, &written, sizeof(candidate)) != 1 || written != 16)
		goto out;
	memcpy(output, candidate, sizeof(candidate));
	result = 0;
out:
	if (result)
		OPENSSL_cleanse(output, 16);
	OPENSSL_cleanse(candidate, sizeof(candidate));
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(algorithm);
	return result;
}

static inline int
jcop4_sm_verify_mac8_ex(OSSL_LIB_CTX *libctx, const unsigned char key[16], const unsigned char *input,
		size_t size, const unsigned char received[8])
{
	unsigned char expected[16] = {0};
	int result = 1;
	if (received && !jcop4_sm_cmac_ex(libctx, key, input, size, expected))
		result = CRYPTO_memcmp(expected, received, 8) != 0;
	OPENSSL_cleanse(expected, sizeof(expected));
	return result;
}

#endif
