/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Offline candidate anonymous CA/P-521/AES128 preparation.
 * Does not establish/authenticate a channel, send APDU or handle a PIN.
 * Outputs are pending until setup AND a protected response are verified. */
#ifndef JCOP4_CHANNEL_AGREEMENT_H
#define JCOP4_CHANNEL_AGREEMENT_H

#include "jcop4-channel-kdf.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#define JCOP4_P521_POINT_SIZE 133
struct jcop4_ca_pending {
	unsigned char terminal_public[JCOP4_P521_POINT_SIZE];
	struct jcop4_channel_keys keys;
};

static inline void
jcop4_ca_pending_clear(struct jcop4_ca_pending *pending)
{
	if (pending)
		OPENSSL_cleanse(pending, sizeof(*pending));
}

/* Only canonical uncompressed SEC1 P-521 points. Mathematical validation,
 * not proof of card identity, provenance or permission to authenticate. */
static inline int
jcop4_p521_public_valid(const unsigned char *encoded, size_t size)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL, *prime = NULL;
	int valid = 0;
	if (!encoded || size != JCOP4_P521_POINT_SIZE || encoded[0] != 4)
		return 0;
	group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	if (group)
		point = EC_POINT_new(group);
	x = BN_bin2bn(encoded + 1, 66, NULL);
	y = BN_bin2bn(encoded + 67, 66, NULL);
	prime = BN_new();
	if (group && point && x && y && prime && EC_GROUP_get_curve(group, prime, NULL, NULL, NULL) == 1 &&
			BN_cmp(x, prime) < 0 && BN_cmp(y, prime) < 0 &&
			EC_POINT_set_affine_coordinates(group, point, x, y, NULL) == 1 &&
			EC_POINT_is_at_infinity(group, point) == 0 && EC_POINT_is_on_curve(group, point, NULL) == 1)
		valid = 1;
	BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(prime);
	EC_POINT_clear_free(point);
	EC_GROUP_free(group);
	return valid;
}

/* Common implementation. The production entry point below generates the
 * ephemeral key internally; tests inject public deterministic fixtures here.
 * Caller retains ownership of local_key. No private scalar is exported. */
static inline int
jcop4_ca_prepare_key_ex(OSSL_LIB_CTX *libctx, EVP_PKEY *local_key, const unsigned char *peer,
		size_t peer_size, struct jcop4_ca_pending *pending)
{
	struct jcop4_ca_pending candidate = {
			{0},
			{{0}, {0}, {0}}
	       };
	EVP_PKEY_CTX *import = NULL, *check = NULL, *derive = NULL;
	EVP_PKEY *peer_key = NULL;
	unsigned char secret[66] = {0};
	char name[80] = {0}, group_name[] = "secp521r1", no_kdf[] = "";
	size_t name_size = 0, public_size = 0, secret_size = sizeof(secret);
	int cofactor = 0, result = 1;
	unsigned int pad = 1;
	OSSL_PARAM public_params[3], derive_params[4];
	if (!pending)
		return 1;
	if (!local_key || !jcop4_p521_public_valid(peer, peer_size) || EVP_PKEY_is_a(local_key, "EC") != 1 ||
			EVP_PKEY_get_utf8_string_param(local_key, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof(name), &name_size) != 1 ||
			(strcmp(name, "secp521r1") && strcmp(name, "P-521")))
		goto out;
	check = EVP_PKEY_CTX_new_from_pkey(libctx, local_key, NULL);
	if (!check || EVP_PKEY_param_check(check) != 1 || EVP_PKEY_private_check(check) != 1 ||
			EVP_PKEY_pairwise_check(check) != 1 ||
			EVP_PKEY_get_octet_string_param(local_key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
					candidate.terminal_public, sizeof(candidate.terminal_public), &public_size) != 1 ||
			!jcop4_p521_public_valid(candidate.terminal_public, public_size))
		goto out;
	public_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
	public_params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)peer, peer_size);
	public_params[2] = OSSL_PARAM_construct_end();
	import = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
	if (!import || EVP_PKEY_fromdata_init(import) != 1 ||
			EVP_PKEY_fromdata(import, &peer_key, EVP_PKEY_PUBLIC_KEY, public_params) != 1)
		goto out;
	EVP_PKEY_CTX_free(check);
	check = EVP_PKEY_CTX_new_from_pkey(libctx, peer_key, NULL);
	if (!check || EVP_PKEY_public_check(check) != 1)
		goto out;
	derive = EVP_PKEY_CTX_new_from_pkey(libctx, local_key, NULL);
	derive_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, no_kdf, 0);
	derive_params[1] = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &cofactor);
	derive_params[2] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
	derive_params[3] = OSSL_PARAM_construct_end();
	if (!derive || EVP_PKEY_derive_init_ex(derive, derive_params) != 1 ||
			EVP_PKEY_derive_set_peer(derive, peer_key) != 1 ||
			EVP_PKEY_derive(derive, secret, &secret_size) != 1 || secret_size != sizeof(secret) ||
			jcop4_ca_aes128_kdf_ex(libctx, secret, secret_size, &candidate.keys))
		goto out;
	memcpy(pending, &candidate, sizeof(candidate));
	result = 0;
out:
	if (result)
		jcop4_ca_pending_clear(pending);
	jcop4_ca_pending_clear(&candidate);
	OPENSSL_cleanse(secret, sizeof(secret));
	EVP_PKEY_CTX_free(import);
	EVP_PKEY_CTX_free(check);
	EVP_PKEY_CTX_free(derive);
	EVP_PKEY_free(peer_key);
	return result;
}

/* Context/provider policy applies to key generation, validation, import,
 * ECDH and KDF. No provider loading, property override or global fallback. */
static inline int
jcop4_ca_prepare_ex(OSSL_LIB_CTX *libctx, const unsigned char *peer,
		size_t peer_size, struct jcop4_ca_pending *pending)
{
	EVP_PKEY *ephemeral = NULL;
	EVP_PKEY_CTX *keygen = NULL;
	int result = 1;
	char group[] = "secp521r1";
	OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
			OSSL_PARAM_construct_end()};
	if (!pending)
		return 1;
	if (jcop4_p521_public_valid(peer, peer_size)) {
		keygen = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
		if (keygen && EVP_PKEY_keygen_init(keygen) == 1 &&
				EVP_PKEY_CTX_set_params(keygen, params) == 1 && EVP_PKEY_generate(keygen, &ephemeral) == 1)
			result = jcop4_ca_prepare_key_ex(libctx, ephemeral, peer, peer_size, pending);
	}
	EVP_PKEY_CTX_free(keygen);
	EVP_PKEY_free(ephemeral);
	if (result)
		jcop4_ca_pending_clear(pending);
	return result;
}

/* Canonical wire bytes shared by the transport validator so the accepted
 * commands cannot drift from the constructed ones. */
#define JCOP4_CA_MSE_BYTES {0x00, 0x22, 0x41, 0xA4, 0x0C, 0x80, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02}
#define JCOP4_CA_GA_PREFIX_BYTES {0x10, 0x86, 0x00, 0x00, 0x8B, 0x7C, 0x81, 0x88, 0x80, 0x81, 0x85}

/* Candidate wire bytes for the reviewed plain transport path, not a sender.
 * MSE/GA constructor Le=0 (absent), serializer copies CLA unchanged. Other
 * runtime pipes/profiles remain unproven: never use as channel confirmation. */
static inline int
jcop4_ca_build_mse(unsigned char *out, size_t capacity, size_t *written)
{
	static const unsigned char candidate[] = JCOP4_CA_MSE_BYTES;
	if (!written)
		return 1;
	*written = 0;
	if (!out || capacity < sizeof(candidate))
		return 1;
	memcpy(out, candidate, sizeof(candidate));
	*written = sizeof(candidate);
	return 0;
}

static inline int
jcop4_ca_build_ga(const unsigned char *terminal_public, size_t size,
		unsigned char *out, size_t capacity, size_t *written)
{
	/* Lc139, 7C length136, 80 length133, SEC1 prefix04; no trailing Le. */
	static const unsigned char prefix[] = JCOP4_CA_GA_PREFIX_BYTES;
	unsigned char candidate[sizeof(prefix) + JCOP4_P521_POINT_SIZE];
	if (!written)
		return 1;
	*written = 0;
	if (!out || capacity < sizeof(candidate) || !jcop4_p521_public_valid(terminal_public, size))
		return 1;
	memcpy(candidate, prefix, sizeof(prefix));
	memcpy(candidate + sizeof(prefix), terminal_public, size);
	memcpy(out, candidate, sizeof(candidate));
	*written = sizeof(candidate);
	return 0;
}

#endif
