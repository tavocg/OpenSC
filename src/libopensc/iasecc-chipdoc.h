/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Internal ChipDoc profile and operation state. No transport or cryptography.
 * Response transitions are for a future adapter AFTER MAC verification; this
 * state machine does not authenticate a response or authorize card I/O itself.
 */
#ifndef OPENSC_IASECC_CHIPDOC_H
#define OPENSC_IASECC_CHIPDOC_H

#include "opensc.h"
#include <stdint.h>
#include <string.h>

/* Public PIN formatting only; never credential bytes or cached login state. */
struct iasecc_chipdoc_pin_policy {
	size_t minimum, maximum;
	unsigned int format, flags;
};

enum iasecc_chipdoc_profile_id {
	IASECC_CHIPDOC_NONE,
	IASECC_CHIPDOC_CR_RSA2048
};

struct iasecc_chipdoc_profile {
	enum iasecc_chipdoc_profile_id id;
	const unsigned char *atr, *aid;
	size_t atr_len, aid_len;
	unsigned int dh_file, dh_size, curve_selector;
	unsigned int pin_reference, observed_available;
	unsigned int signing_reference, signing_bits, signing_algorithm;
	size_t min_send, min_receive;
};

/* Validated public metadata supplied by the future PKCS#15/D004 adapter.
 * ATR+AID can be shared by other personalizations (including eOI); neither
 * selects a usable session without these additional observed properties. */
struct iasecc_chipdoc_metadata {
	unsigned int algorithm, reference, bits, pin_reference;
	unsigned int dh_file, dh_size, curve_selector;
	int native, signing;
};

static inline const struct iasecc_chipdoc_profile *
iasecc_chipdoc_profile(enum iasecc_chipdoc_profile_id id)
{
	static const unsigned char atr[] = {0x3B, 0xD5, 0x18, 0xFF, 0x81, 0x91, 0xFE, 0x1F, 0xC3, 0x80, 0x73, 0xC8, 0x21, 0x10, 0x0A};
	static const unsigned char aid[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0, 0, 3, 0x63, 0x64, 0x79, 0x6E, 0x69, 0x64};
	/* The D004 discriminator is decimal18 (0x12), NOT hexadecimal0x18. */
	static const struct iasecc_chipdoc_profile cr = {
			IASECC_CHIPDOC_CR_RSA2048, atr, aid, sizeof(atr), sizeof(aid),
			0xD004, 137, 18, 1, 7, 0x91, 2048, 0x28, 139, 291};
	return id == cr.id ? &cr : NULL;
}

/* A candidate profile only; not channel identity, card capability or a driver
 * binding. A shared ATR without this application cannot select the profile. */
static inline enum iasecc_chipdoc_profile_id
iasecc_chipdoc_candidate(const struct sc_atr *atr, const struct sc_aid *aid)
{
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	if (!atr || !aid || atr->len != p->atr_len || aid->len != p->aid_len ||
			memcmp(atr->value, p->atr, p->atr_len) || memcmp(aid->value, p->aid, p->aid_len))
		return IASECC_CHIPDOC_NONE;
	return p->id;
}

/* The normal OpenSC dispatcher will validate both card and reader limits.
 * Never set capability bits here to make a failing transport check pass. */
static inline int
iasecc_chipdoc_transport(const struct sc_card *card,
		enum iasecc_chipdoc_profile_id id)
{
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(id);
	if (!p || !card || !card->reader || card->atr.len != p->atr_len ||
			card->reader->atr.len != p->atr_len || memcmp(card->atr.value, p->atr, p->atr_len) ||
			memcmp(card->reader->atr.value, p->atr, p->atr_len) ||
			card->reader->active_protocol != SC_PROTO_T1 || !(card->caps & SC_CARD_CAP_APDU_EXT) ||
			card->max_send_size < p->min_send || card->max_recv_size < p->min_receive ||
			card->reader->max_send_size < p->min_send || card->reader->max_recv_size < p->min_receive)
		return SC_ERROR_NOT_SUPPORTED;
	return SC_SUCCESS;
}

enum iasecc_chipdoc_phase {
	IASECC_CHIPDOC_INACTIVE,
	IASECC_CHIPDOC_PREPARED,
	IASECC_CHIPDOC_CHANNEL,
	IASECC_CHIPDOC_MF,
	IASECC_CHIPDOC_PIN_AVAILABLE,
	IASECC_CHIPDOC_LOGGED_IN,
	IASECC_CHIPDOC_APPLICATION,
	IASECC_CHIPDOC_MSE,
	IASECC_CHIPDOC_BOOTSTRAPPING
};
enum iasecc_chipdoc_response {
	IASECC_CHIPDOC_RESPONSE_MF,
	IASECC_CHIPDOC_RESPONSE_QUERY,
	IASECC_CHIPDOC_RESPONSE_LOGIN,
	IASECC_CHIPDOC_RESPONSE_APPLICATION,
	IASECC_CHIPDOC_RESPONSE_MSE,
	IASECC_CHIPDOC_RESPONSE_SIGNATURE
};

/* One owned opaque crypto context per card. No PIN/hash/digest/signature or
 * persistent retry counter. Generation prevents a reply from an earlier
 * context being applied after logout/reset/replacement. Zero-initialize. */
struct iasecc_chipdoc_session {
	enum iasecc_chipdoc_profile_id profile;
	enum iasecc_chipdoc_phase phase;
	uint64_t generation;
	void *channel;
	void (*clear_channel)(void *);
	unsigned int key_reference, key_bits;
};

static inline void
iasecc_chipdoc_invalidate(struct iasecc_chipdoc_session *s)
{
	void *channel;
	void (*clear)(void *);
	uint64_t generation;
	if (!s)
		return;
	channel = s->channel;
	clear = s->clear_channel;
	generation = s->generation == UINT64_MAX ? UINT64_MAX : s->generation + 1;
	/* Detach before invoking cleanup, including recursive invalidation. */
	sc_mem_clear(s, sizeof(*s));
	s->generation = generation;
	if (channel && clear)
		clear(channel);
}

/* Reserve a local bootstrap generation so the reset lifecycle hook can
 * invalidate it even BEFORE a permanent profile has been recognized. */
static inline int
iasecc_chipdoc_begin_bootstrap(struct iasecc_chipdoc_session *s,
		enum iasecc_chipdoc_profile_id candidate)
{
	if (!s || !iasecc_chipdoc_profile(candidate) || s->phase != IASECC_CHIPDOC_INACTIVE ||
			s->profile || s->channel || s->clear_channel)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (s->generation == UINT64_MAX)
		return SC_ERROR_NOT_ALLOWED;
	s->generation++;
	s->profile = candidate;
	s->phase = IASECC_CHIPDOC_BOOTSTRAPPING;
	return SC_SUCCESS;
}

/* No ownership transfer on failure. Starting again requires explicit local
 * invalidation; this routine never replaces/retries a live session. */
static inline int
iasecc_chipdoc_prepare(struct iasecc_chipdoc_session *s,
		const struct sc_card *card, const struct sc_aid *aid, const struct iasecc_chipdoc_metadata *metadata)
{
	enum iasecc_chipdoc_profile_id id;
	const struct iasecc_chipdoc_profile *p;
	if (!s || !card || s->phase != IASECC_CHIPDOC_INACTIVE || s->profile || s->channel || s->clear_channel)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (s->generation == UINT64_MAX)
		return SC_ERROR_NOT_ALLOWED;
	id = iasecc_chipdoc_candidate(&card->atr, aid);
	p = iasecc_chipdoc_profile(id);
	if (!p || !metadata || metadata->algorithm != SC_ALGORITHM_RSA || metadata->reference != p->signing_reference ||
			metadata->bits != p->signing_bits || metadata->pin_reference != p->pin_reference ||
			metadata->dh_file != p->dh_file || metadata->dh_size != p->dh_size || metadata->curve_selector != p->curve_selector ||
			metadata->native != 1 || metadata->signing != 1 || iasecc_chipdoc_transport(card, id))
		return SC_ERROR_NOT_SUPPORTED;
	s->generation++;
	s->profile = id;
	s->phase = IASECC_CHIPDOC_PREPARED;
	return SC_SUCCESS;
}

/* Caller has already established and authenticated the channel. The owning
 * cleanup callback must cleanse/free its keys/SSC; caller retains ownership
 * if this function refuses attachment. No keys or proof booleans are copied. */
static inline int
iasecc_chipdoc_attach(struct iasecc_chipdoc_session *s,
		uint64_t generation, void *channel, void (*clear)(void *))
{
	if (!s || !channel || !clear || s->phase != IASECC_CHIPDOC_PREPARED ||
			!iasecc_chipdoc_profile(s->profile) || generation != s->generation || s->channel || s->clear_channel)
		return SC_ERROR_INVALID_ARGUMENTS;
	s->channel = channel;
	s->clear_channel = clear;
	s->phase = IASECC_CHIPDOC_CHANNEL;
	return SC_SUCCESS;
}

/* Validate local metadata BEFORE MSE. Only the measured signing key/hash is
 * supported initially. References/sizes come from the caller's PKCS#15 data. */
static inline int
iasecc_chipdoc_signing_key(const struct iasecc_chipdoc_session *s,
		unsigned int reference, unsigned int bits, unsigned long flags)
{
	const struct iasecc_chipdoc_profile *p = s ? iasecc_chipdoc_profile(s->profile) : NULL;
	if (!p || reference != p->signing_reference || bits != p->signing_bits ||
			flags != (SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256))
		return SC_ERROR_NOT_SUPPORTED;
	if (s->phase != IASECC_CHIPDOC_APPLICATION || !s->channel || !s->clear_channel)
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	return SC_SUCCESS;
}

/* AFTER MAC, padding, expected response content and inner/outer SW policy
 * verification in the future adapter. This function cannot verify those
 * conditions. Unexpected/stale/authenticated-error replies discard all
 * operation state; no transition automatically sends a command. */
static inline int
iasecc_chipdoc_record(struct iasecc_chipdoc_session *s,
		uint64_t generation, enum iasecc_chipdoc_response response, unsigned int sw,
		unsigned int key_reference, unsigned int key_bits)
{
	const struct iasecc_chipdoc_profile *p;
	enum iasecc_chipdoc_phase before, after;
	if (!s)
		return SC_ERROR_INVALID_ARGUMENTS;
	p = iasecc_chipdoc_profile(s->profile);
	if (!p || !s->channel || !s->clear_channel || generation != s->generation)
		goto invalid;
	if (response == IASECC_CHIPDOC_RESPONSE_MF) {
		before = IASECC_CHIPDOC_CHANNEL;
		after = IASECC_CHIPDOC_MF;
	} else if (response == IASECC_CHIPDOC_RESPONSE_QUERY) {
		before = IASECC_CHIPDOC_MF;
		after = IASECC_CHIPDOC_PIN_AVAILABLE;
	} else if (response == IASECC_CHIPDOC_RESPONSE_LOGIN) {
		before = IASECC_CHIPDOC_PIN_AVAILABLE;
		after = IASECC_CHIPDOC_LOGGED_IN;
	} else if (response == IASECC_CHIPDOC_RESPONSE_APPLICATION) {
		before = IASECC_CHIPDOC_LOGGED_IN;
		after = IASECC_CHIPDOC_APPLICATION;
	} else if (response == IASECC_CHIPDOC_RESPONSE_MSE) {
		before = IASECC_CHIPDOC_APPLICATION;
		after = IASECC_CHIPDOC_MSE;
	} else if (response == IASECC_CHIPDOC_RESPONSE_SIGNATURE) {
		before = IASECC_CHIPDOC_MSE;
		after = IASECC_CHIPDOC_APPLICATION;
	} else
		goto invalid;
	if (s->phase != before || sw != (response == IASECC_CHIPDOC_RESPONSE_QUERY ? 0x63C0 + p->observed_available : 0x9000))
		goto invalid;
	if (response == IASECC_CHIPDOC_RESPONSE_MSE) {
		if (key_reference != p->signing_reference || key_bits != p->signing_bits)
			goto invalid;
		s->key_reference = key_reference;
		s->key_bits = key_bits;
	} else if (key_reference || key_bits)
		goto invalid;
	if (response == IASECC_CHIPDOC_RESPONSE_SIGNATURE)
		s->key_reference = s->key_bits = 0;
	s->phase = after;
	return SC_SUCCESS;
invalid:
	iasecc_chipdoc_invalidate(s);
	return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
}

#endif
