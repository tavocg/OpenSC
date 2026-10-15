/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Candidate codec for the reviewed AES128/IV=AES(Kenc,SSC)/MAC8 branch.
 * Does not serialize transport Lc/Le, perform card I/O or establish a channel.
 * Initialize only with fresh session keys after a separately verified setup. */
#ifndef JCOP4_CHANNEL_MESSAGES_H
#define JCOP4_CHANNEL_MESSAGES_H

#include "jcop4-channel-kdf.h"
#include "jcop4-channel-primitives.h"

#define JCOP4_SM_DATA_LIMIT 3584
enum jcop4_sm_phase { JCOP4_SM_INVALID,
	JCOP4_SM_IDLE,
	JCOP4_SM_WAITING };
struct jcop4_sm_channel {
	struct jcop4_channel_keys keys;
	enum jcop4_sm_phase phase;
};

static inline void
jcop4_sm_invalidate(struct jcop4_sm_channel *channel)
{
	if (channel) {
		OPENSSL_cleanse(channel, sizeof(*channel));
		channel->phase = JCOP4_SM_INVALID;
	}
}

static inline int
jcop4_sm_init(struct jcop4_sm_channel *channel, const struct jcop4_channel_keys *keys)
{
	if (!channel)
		return 1;
	if (!keys) {
		jcop4_sm_invalidate(channel);
		return 1;
	}
	memcpy(&channel->keys, keys, sizeof(*keys));
	channel->phase = JCOP4_SM_IDLE;
	return 0;
}

/* One CBC block with zero input IV equals AES-ECB(Kenc, current SSC).
 * This is the IV for the message data, not a zero data IV. */
static inline int
jcop4_sm_ssc_iv_ex(OSSL_LIB_CTX *libctx, const unsigned char key[16], const unsigned char ssc[16], unsigned char iv[16])
{
	const unsigned char zero[16] = {0};
	return jcop4_sm_aes128_cbc_ex(libctx, 1, key, zero, ssc, 16, iv, 16);
}

static inline int
jcop4_sm_ssc_iv(const unsigned char key[16], const unsigned char ssc[16], unsigned char iv[16])
{
	return jcop4_sm_ssc_iv_ex(NULL, key, ssc, iv);
}

static inline int
jcop4_sm_append_tlv(unsigned char *out, size_t capacity, size_t *size,
		unsigned char tag, const unsigned char *value, size_t length)
{
	size_t header = length < 128 ? 2 : length <= 255 ? 3
							 : 4;
	if (!out || !size || (!value && length) || length > JCOP4_SM_CRYPTO_LIMIT ||
			*size > capacity || header > capacity - *size || length > capacity - *size - header)
		return 1;
	out[(*size)++] = tag;
	if (header == 2)
		out[(*size)++] = (unsigned char)length;
	else {
		out[(*size)++] = header == 3 ? 0x81 : 0x82;
		if (header == 4)
			out[(*size)++] = (unsigned char)(length >> 8);
		out[(*size)++] = (unsigned char)length;
	}
	if (length)
		memcpy(out + *size, value, length);
	*size += length;
	return 0;
}

/* Canonical, bounded, single-byte tags only; no nested/indefinite TLV. */
static inline int
jcop4_sm_take_tlv(const unsigned char *input, size_t size, size_t *offset,
		unsigned char tag, const unsigned char **value, size_t *length)
{
	size_t pos, count;
	unsigned int first;
	if (!input || !offset || !value || !length || *offset > size || size - *offset < 2)
		return 1;
	pos = *offset;
	if (input[pos++] != tag)
		return 1;
	first = input[pos++];
	if (first < 128)
		*length = first;
	else {
		count = first & 0x7F;
		if (!count || count > 2 || count > size - pos || !input[pos])
			return 1;
		*length = input[pos++];
		if (count == 2)
			*length = (*length << 8) | input[pos++];
		if (*length < 128 || (count == 2 && *length <= 255))
			return 1;
	}
	if (*length > size - pos)
		return 1;
	*value = input + pos;
	*offset = pos + *length;
	return 0;
}

/* Emits a protected header and body, not a complete wire APDU. The caller
 * retains responsibility for transport limits, operation authorization and
 * ending the channel on a transport failure. No credential/data logging. */
enum jcop4_sm_le_encoding { JCOP4_SM_LE_SHORT,
	JCOP4_SM_LE_TWO_BYTE_256 };
static inline int
jcop4_sm_seal_policy_ex(OSSL_LIB_CTX *libctx, struct jcop4_sm_channel *channel, const unsigned char header[4],
		const unsigned char *data, size_t data_size, int has_le, unsigned int le,
		unsigned char protected_header[4], unsigned char *body, size_t capacity, size_t *written,
		enum jcop4_sm_le_encoding encoding)
{
	unsigned char next[16] = {0}, iv[16] = {0}, mac[16] = {0}, local_header[4];
	unsigned char padded[JCOP4_SM_CRYPTO_LIMIT] = {0}, encrypted[JCOP4_SM_CRYPTO_LIMIT] = {0};
	unsigned char candidate[JCOP4_SM_CRYPTO_LIMIT] = {0}, authenticated[JCOP4_SM_CRYPTO_LIMIT] = {0};
	size_t padded_size = 0, body_size = 0, auth_size = 32;
	int result = 1;
	if (!written)
		return 1;
	*written = 0;
	if (!channel || channel->phase != JCOP4_SM_IDLE || !header || header[0] != 0 ||
			(!data && data_size) || data_size > JCOP4_SM_DATA_LIMIT || !protected_header || !body ||
			(has_le != 0 && has_le != 1) || (has_le && (!le || le > 256)) ||
			(encoding != JCOP4_SM_LE_SHORT && encoding != JCOP4_SM_LE_TWO_BYTE_256) ||
			(encoding == JCOP4_SM_LE_TWO_BYTE_256 && (!has_le || le != 256)))
		goto out;
	if (jcop4_sm_next_ssc(channel->keys.ssc, next)) {
		jcop4_sm_invalidate(channel);
		goto out;
	}
	memcpy(local_header, header, 4);
	local_header[0] = 0x0C;
	memcpy(authenticated, next, 16);
	if (jcop4_sm_pad(local_header, 4, authenticated + 16, sizeof(authenticated) - 16, &padded_size))
		goto out;
	if (data_size) {
		if (jcop4_sm_pad(data, data_size, padded, sizeof(padded), &padded_size) ||
				jcop4_sm_ssc_iv_ex(libctx, channel->keys.encryption, next, iv) ||
				jcop4_sm_aes128_cbc_ex(libctx, 1, channel->keys.encryption, iv, padded, padded_size,
						encrypted + 1, sizeof(encrypted) - 1))
			goto out;
		encrypted[0] = 1;
		if (jcop4_sm_append_tlv(candidate, sizeof(candidate), &body_size, 0x87, encrypted, padded_size + 1))
			goto out;
	}
	if (has_le) {
		unsigned char encoded[2] = {le == 256 ? 0 : (unsigned char)le, 0};
		size_t encoded_size = 1;
		if (encoding == JCOP4_SM_LE_TWO_BYTE_256) {
			encoded[0] = 1;
			encoded_size = 2;
		}
		if (jcop4_sm_append_tlv(candidate, sizeof(candidate), &body_size, 0x97, encoded, encoded_size))
			goto out;
	}
	if (body_size) {
		memcpy(authenticated + 32, candidate, body_size);
		if (jcop4_sm_pad(authenticated, 32 + body_size, authenticated, sizeof(authenticated), &auth_size))
			goto out;
	}
	if (jcop4_sm_cmac_ex(libctx, channel->keys.mac, authenticated, auth_size, mac) ||
			jcop4_sm_append_tlv(candidate, sizeof(candidate), &body_size, 0x8E, mac, 8) || capacity < body_size)
		goto out;
	memcpy(protected_header, local_header, 4);
	memcpy(body, candidate, body_size);
	memcpy(channel->keys.ssc, next, 16);
	channel->phase = JCOP4_SM_WAITING;
	*written = body_size;
	result = 0;
out:
	OPENSSL_cleanse(next, sizeof(next));
	OPENSSL_cleanse(mac, sizeof(mac));
	OPENSSL_cleanse(iv, sizeof(iv));
	OPENSSL_cleanse(padded, sizeof(padded));
	OPENSSL_cleanse(encrypted, sizeof(encrypted));
	OPENSSL_cleanse(candidate, sizeof(candidate));
	OPENSSL_cleanse(authenticated, sizeof(authenticated));
	return result;
}

/* The caller owns libctx and must retain the same context for the channel.
 * NULL is the explicit standalone default, never retry after _ex failure. */
static inline int
jcop4_sm_seal_policy(struct jcop4_sm_channel *channel, const unsigned char header[4],
		const unsigned char *data, size_t data_size, int has_le, unsigned int le,
		unsigned char protected_header[4], unsigned char *body, size_t capacity, size_t *written,
		enum jcop4_sm_le_encoding encoding)
{
	return jcop4_sm_seal_policy_ex(NULL, channel, header, data, data_size, has_le, le,
			protected_header, body, capacity, written, encoding);
}

/* Existing callers retain the exact original short DO97 encoding. */
static inline int
jcop4_sm_seal(struct jcop4_sm_channel *channel, const unsigned char header[4],
		const unsigned char *data, size_t data_size, int has_le, unsigned int le,
		unsigned char protected_header[4], unsigned char *body, size_t capacity, size_t *written)
{
	return jcop4_sm_seal_policy(channel, header, data, data_size, has_le, le,
			protected_header, body, capacity, written, JCOP4_SM_LE_SHORT);
}

/* Fixed diagnostic enums only: no response bytes, status, lengths or keys.
 * MAC verification is separate from acceptance (padding/capacity may fail).
 * A pre-MAC structural observation is not authenticated card information. */
enum jcop4_sm_decode_result {
	JCOP4_SM_DECODE_ARGUMENT,
	JCOP4_SM_DECODE_SIZE,
	JCOP4_SM_DECODE_OUTER_SW,
	JCOP4_SM_DECODE_SSC,
	JCOP4_SM_DECODE_CIPHER_TLV,
	JCOP4_SM_DECODE_STATUS_TLV,
	JCOP4_SM_DECODE_MAC_TLV,
	JCOP4_SM_DECODE_MAC,
	JCOP4_SM_DECODE_DECRYPT,
	JCOP4_SM_DECODE_PADDING,
	JCOP4_SM_DECODE_CAPACITY,
	JCOP4_SM_DECODE_OK,
	JCOP4_SM_DECODE_STATUS_MISMATCH
};
/* Explicit opt-ins for observed response families. No policy accepts a bare
 * status or bypasses MAC/structure validation. The PSO policy accepts only
 * the complete status-only16-byte error envelope, never signature data. */
enum jcop4_sm_outer_policy { JCOP4_SM_OUTER_9000,
	JCOP4_SM_OUTER_9000_OR_MATCHING_63CX,
	JCOP4_SM_OUTER_PSO_STATUS_6A82 };
enum jcop4_sm_mac_result { JCOP4_SM_MAC_NOT_CHECKED,
	JCOP4_SM_MAC_FAILED,
	JCOP4_SM_MAC_VERIFIED };
struct jcop4_sm_decode_report {
	enum jcop4_sm_decode_result result;
	enum jcop4_sm_mac_result mac;
};
static inline const char *
jcop4_sm_decode_name(enum jcop4_sm_decode_result result)
{
	switch (result) {
	case JCOP4_SM_DECODE_ARGUMENT:
		return "invalid_arguments_or_state";
	case JCOP4_SM_DECODE_SIZE:
		return "response_size_invalid";
	case JCOP4_SM_DECODE_OUTER_SW:
		return "outer_sw_not_9000";
	case JCOP4_SM_DECODE_SSC:
		return "ssc_overflow";
	case JCOP4_SM_DECODE_CIPHER_TLV:
		return "encrypted_object_invalid";
	case JCOP4_SM_DECODE_STATUS_TLV:
		return "status_object_invalid_or_unsupported";
	case JCOP4_SM_DECODE_MAC_TLV:
		return "mac_object_invalid_or_trailing_data";
	case JCOP4_SM_DECODE_MAC:
		return "mac_verification_failed";
	case JCOP4_SM_DECODE_DECRYPT:
		return "decryption_failed";
	case JCOP4_SM_DECODE_PADDING:
		return "padding_invalid";
	case JCOP4_SM_DECODE_CAPACITY:
		return "plaintext_capacity_exceeded";
	case JCOP4_SM_DECODE_OK:
		return "accepted";
	case JCOP4_SM_DECODE_STATUS_MISMATCH:
		return "authenticated_status_outer_mismatch";
	}
	return "unknown_local_result";
}

/* Conservative response subset: optional encrypted87/01, then99/2,8E/8,
 * physical SW9000 by default. The explicit PIN-query policy additionally
 * permits outer63Cx only when it matches MAC-authenticated DO99 exactly.
 * The PSO-only policy requires outer6A82, canonical99/2+8E/8 and no data.
 * No other tags/alternatives or fallback. An authenticated
 * inner error SW is returned as such, never converted into success. */
static inline int
jcop4_sm_open_report_policy_ex(OSSL_LIB_CTX *libctx, struct jcop4_sm_channel *channel, const unsigned char *response,
		size_t size, unsigned char *plain, size_t capacity, size_t *written, unsigned int *sw,
		enum jcop4_sm_outer_policy policy, struct jcop4_sm_decode_report *report)
{
	unsigned char next[16] = {0}, iv[16] = {0};
	unsigned char authenticated[JCOP4_SM_CRYPTO_LIMIT] = {0}, decrypted[JCOP4_SM_CRYPTO_LIMIT] = {0};
	const unsigned char *ciphertext = NULL, *status = NULL, *tag = NULL;
	size_t offset = 0, cipher_size = 0, length = 0, auth_end = 0, auth_size = 0, plain_size = 0;
	unsigned int inner_sw = 0, outer_sw = 0;
	struct jcop4_sm_decode_report local = {JCOP4_SM_DECODE_ARGUMENT, JCOP4_SM_MAC_NOT_CHECKED};
	int result = 1;
	if (written)
		*written = 0;
	if (sw)
		*sw = 0;
	if (!channel || channel->phase != JCOP4_SM_WAITING || !written || !sw || !plain || !response ||
			(policy != JCOP4_SM_OUTER_9000 && policy != JCOP4_SM_OUTER_9000_OR_MATCHING_63CX &&
					policy != JCOP4_SM_OUTER_PSO_STATUS_6A82))
		goto out;
	local.result = JCOP4_SM_DECODE_SIZE;
	if (size < 2 || size > JCOP4_SM_CRYPTO_LIMIT - 32)
		goto out;
	local.result = JCOP4_SM_DECODE_OUTER_SW;
	outer_sw = (unsigned int)response[size - 2] * 256 + response[size - 1];
	if (policy == JCOP4_SM_OUTER_PSO_STATUS_6A82) {
		if (outer_sw != 0x6A82 || size != 16 || response[0] != 0x99)
			goto out;
	} else if (outer_sw != 0x9000 && !(policy == JCOP4_SM_OUTER_9000_OR_MATCHING_63CX && (outer_sw & 0xFFF0) == 0x63C0))
		goto out;
	local.result = JCOP4_SM_DECODE_SIZE;
	if (size < 16)
		goto out;
	local.result = JCOP4_SM_DECODE_SSC;
	if (jcop4_sm_next_ssc(channel->keys.ssc, next))
		goto out;
	if (response[0] == 0x87) {
		local.result = JCOP4_SM_DECODE_CIPHER_TLV;
		if (jcop4_sm_take_tlv(response, size - 2, &offset, 0x87, &ciphertext, &length) ||
				length < 17 || ciphertext[0] != 1 || (length - 1) % 16 ||
				length - 1 > JCOP4_SM_DATA_LIMIT + 16)
			goto out;
		ciphertext++;
		cipher_size = length - 1;
	}
	local.result = JCOP4_SM_DECODE_STATUS_TLV;
	if (jcop4_sm_take_tlv(response, size - 2, &offset, 0x99, &status, &length) || length != 2)
		goto out;
	auth_end = offset;
	local.result = JCOP4_SM_DECODE_MAC_TLV;
	if (jcop4_sm_take_tlv(response, size - 2, &offset, 0x8E, &tag, &length) || length != 8 || offset != size - 2)
		goto out;
	memcpy(authenticated, next, 16);
	memcpy(authenticated + 16, response, auth_end);
	local.result = JCOP4_SM_DECODE_MAC;
	local.mac = JCOP4_SM_MAC_FAILED;
	if (jcop4_sm_pad(authenticated, 16 + auth_end, authenticated, sizeof(authenticated), &auth_size) ||
			jcop4_sm_verify_mac8_ex(libctx, channel->keys.mac, authenticated, auth_size, tag))
		goto out;
	local.mac = JCOP4_SM_MAC_VERIFIED;
	inner_sw = (unsigned int)status[0] * 256 + status[1];
	local.result = JCOP4_SM_DECODE_STATUS_MISMATCH;
	if (outer_sw != 0x9000 && inner_sw != outer_sw)
		goto out;
	/* Nothing reaches the caller before MAC, padding and capacity all pass. */
	if (cipher_size) {
		local.result = JCOP4_SM_DECODE_DECRYPT;
		if (jcop4_sm_ssc_iv_ex(libctx, channel->keys.encryption, next, iv) ||
				jcop4_sm_aes128_cbc_ex(libctx, 0, channel->keys.encryption, iv, ciphertext, cipher_size, decrypted, sizeof(decrypted)))
			goto out;
		local.result = JCOP4_SM_DECODE_PADDING;
		if (jcop4_sm_unpad(decrypted, cipher_size, &plain_size))
			goto out;
	}
	local.result = JCOP4_SM_DECODE_CAPACITY;
	if (plain_size > JCOP4_SM_DATA_LIMIT || plain_size > capacity)
		goto out;
	if (plain_size)
		memcpy(plain, decrypted, plain_size);
	*written = plain_size;
	*sw = inner_sw;
	memcpy(channel->keys.ssc, next, 16);
	channel->phase = JCOP4_SM_IDLE;
	local.result = JCOP4_SM_DECODE_OK;
	result = 0;
out:
	if (report)
		*report = local;
	if (result)
		jcop4_sm_invalidate(channel);
	OPENSSL_cleanse(next, sizeof(next));
	OPENSSL_cleanse(authenticated, sizeof(authenticated));
	OPENSSL_cleanse(iv, sizeof(iv));
	OPENSSL_cleanse(decrypted, sizeof(decrypted));
	return result;
}

static inline int
jcop4_sm_open_report_policy(struct jcop4_sm_channel *channel, const unsigned char *response,
		size_t size, unsigned char *plain, size_t capacity, size_t *written, unsigned int *sw,
		enum jcop4_sm_outer_policy policy, struct jcop4_sm_decode_report *report)
{
	return jcop4_sm_open_report_policy_ex(NULL, channel, response, size, plain, capacity, written, sw, policy, report);
}

/* Existing callers retain precisely the same strict outer9000 policy. */
static inline int
jcop4_sm_open_report(struct jcop4_sm_channel *channel, const unsigned char *response,
		size_t size, unsigned char *plain, size_t capacity, size_t *written, unsigned int *sw,
		struct jcop4_sm_decode_report *report)
{
	return jcop4_sm_open_report_policy(channel, response, size, plain, capacity, written, sw, JCOP4_SM_OUTER_9000, report);
}
static inline int
jcop4_sm_open(struct jcop4_sm_channel *channel, const unsigned char *response,
		size_t size, unsigned char *plain, size_t capacity, size_t *written, unsigned int *sw)
{
	return jcop4_sm_open_report(channel, response, size, plain, capacity, written, sw, NULL);
}

#endif
