/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Offline candidate for the reviewed anonymous CA/AES128 branch.
 * No card I/O, key agreement, PIN handling or secure messaging here. */
#ifndef JCOP4_CHANNEL_KDF_H
#define JCOP4_CHANNEL_KDF_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <string.h>

struct jcop4_channel_keys {
	unsigned char encryption[16];
	unsigned char mac[16];
	unsigned char ssc[16];
};

static inline int
jcop4_ca_aes128_kdf_ex(OSSL_LIB_CTX *libctx, const unsigned char *shared_secret, size_t secret_size,
		struct jcop4_channel_keys *keys)
{
	struct jcop4_channel_keys candidate = {{0}, {0}, {0}};
	EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE] = {0};
	unsigned int digest_size = 0;
	int counter, result = 1;
	if (!keys)
		return 1;
	if (!shared_secret || secret_size != 66)
		goto out;
	md = EVP_MD_fetch(libctx, "SHA1", NULL);
	ctx = EVP_MD_CTX_new();
	if (!md || !ctx)
		goto out;
	for (counter = 1; counter <= 2; counter++) {
		const unsigned char encoded_counter[4] = {0, 0, 0, (unsigned char)counter};
		if (EVP_DigestInit_ex2(ctx, md, NULL) != 1 ||
				EVP_DigestUpdate(ctx, shared_secret, secret_size) != 1 ||
				EVP_DigestUpdate(ctx, encoded_counter, sizeof(encoded_counter)) != 1 ||
				EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1 || digest_size != 20)
			goto out;
		memcpy(counter == 1 ? candidate.encryption : candidate.mac, digest, 16);
		OPENSSL_cleanse(digest, sizeof(digest));
	}
	/* Commit both keys together; never expose a partially derived output.
	 * The zero SSC is part of this candidate, not an observed card session. */
	memcpy(keys, &candidate, sizeof(candidate));
	result = 0;
out:
	if (result)
		OPENSSL_cleanse(keys, sizeof(*keys));
	OPENSSL_cleanse(&candidate, sizeof(candidate));
	OPENSSL_cleanse(digest, sizeof(digest));
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
	return result;
}

#endif
