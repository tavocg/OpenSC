/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Candidate no-PIN confirmation sequence, transport supplied by the caller.
 * No PC/SC, reader discovery, Idopte or credential API in this component.
 * Caller must have selected the known ADF/D004 and validated its control and
 * initial137-byte read in the same exclusively owned connection. */
#ifndef JCOP4_CHANNEL_CONFIRMATION_H
#define JCOP4_CHANNEL_CONFIRMATION_H

#include "jcop4-channel-agreement.h"
#include "jcop4-channel-messages.h"

enum jcop4_ca_probe_stage { JCOP4_CA_INPUT,
	JCOP4_CA_PREPARE,
	JCOP4_CA_MSE,
	JCOP4_CA_GA,
	JCOP4_CA_READ };
enum jcop4_ca_probe_outcome {
	JCOP4_CA_INVALID_INPUT,
	JCOP4_CA_CRYPTO_FAILED,
	JCOP4_CA_TRANSPORT_FAILED,
	JCOP4_CA_RESPONSE_SHAPE_FAILED,
	JCOP4_CA_SETUP_SW_FAILED,
	JCOP4_CA_PROTECTED_RESPONSE_FAILED,
	JCOP4_CA_INNER_SW_FAILED,
	JCOP4_CA_CONTENT_MISMATCH,
	JCOP4_CA_READ_CONFIRMED
};
/* Two static branches for this fixed137-byte READ/MAC8, not a fallback list.
 * A hardware caller must justify its policy before setup, never try both. */
enum jcop4_ca_outer_le { JCOP4_CA_LE_BOUND = 172,
	JCOP4_CA_LE_SHORT_MAX = 256 };
struct jcop4_ca_probe_report {
	enum jcop4_ca_probe_stage stage;
	enum jcop4_ca_probe_outcome outcome;
	int transport;
	unsigned int sw;
	int authenticated_response;
	size_t content_size;
	int content_size_equal, content_first_block_equal, content_tail_equal;
};
typedef int (*jcop4_ca_exchange)(void *context, const unsigned char *command, size_t command_size,
		unsigned char *response, size_t capacity, size_t *received);

/* Return0 means exactly one protected READ matched the initial data, not a
 * logged-in token, trusted identity or signing capability.
 * Optional confirmed must be initialized INVALID before entry. An active
 * destination is refused before I/O and preserved so its owner can close it.
 * Only after full confirmation does it receive IDLE state and SSC2. It belongs
 * to this same exclusively owned connection; no reset/reconnect/other client
 * or plaintext operation may be inserted before continuing. The owner must
 * wipe it AND end/reset the remote session on every exit/transport failure.
 * This crypto-only component cannot itself enforce the connection identity.
 * Without confirmed, this operation remains a probe and always wipes state.
 * Callback returns0 for success, receives capacity258 (including physicalSW).
 * No retries, GET RESPONSE, PIN status, VERIFY or post-probe commands. */
static inline int
jcop4_ca_confirm_d004_session_ex(OSSL_LIB_CTX *libctx, const unsigned char *initial, size_t initial_size,
		enum jcop4_ca_outer_le outer_le, jcop4_ca_exchange exchange, void *context,
		struct jcop4_ca_probe_report *report, struct jcop4_sm_channel *confirmed)
{
	struct jcop4_ca_pending pending = {
			{0},
			{{0}, {0}, {0}}
	       };
	struct jcop4_sm_channel channel = {
			{{0}, {0}, {0}},
			JCOP4_SM_INVALID
	};
	unsigned char peer[133] = {0}, command[144] = {0}, response[258] = {0};
	unsigned char header[4] = {0}, body[64] = {0}, plain[137] = {0};
	const unsigned char read_header[4] = {0, 0xB0, 0, 0};
	size_t command_size = 0, received = 0, body_size = 0, plain_size = 0;
	unsigned int inner_sw = 0;
	int result = 1;
	if (!report) {
		if (confirmed && confirmed->phase == JCOP4_SM_INVALID)
			jcop4_sm_invalidate(confirmed);
		return 1;
	}
	memset(report, 0, sizeof(*report));
	if (confirmed && confirmed->phase != JCOP4_SM_INVALID)
		return 1;
	if (confirmed)
		jcop4_sm_invalidate(confirmed);
	if (!initial || initial_size != 137 || initial[2] != 18 || !exchange ||
			(outer_le != JCOP4_CA_LE_BOUND && outer_le != JCOP4_CA_LE_SHORT_MAX))
		goto out;
	peer[0] = 4;
	memcpy(peer + 1, initial + 5, 132);
	if (!jcop4_p521_public_valid(peer, sizeof(peer)))
		goto out;
	report->stage = JCOP4_CA_PREPARE;
	report->outcome = JCOP4_CA_CRYPTO_FAILED;
	if (jcop4_ca_prepare_ex(libctx, peer, sizeof(peer), &pending) ||
			jcop4_ca_build_mse(command, sizeof(command), &command_size))
		goto out;
	for (int step = 0; step < 2; step++) {
		report->stage = step ? JCOP4_CA_GA : JCOP4_CA_MSE;
		report->sw = 0;
		report->outcome = JCOP4_CA_TRANSPORT_FAILED;
		received = 0;
		memset(response, 0, sizeof(response));
		report->transport = exchange(context, command, command_size, response, sizeof(response), &received);
		if (report->transport)
			goto out;
		report->outcome = JCOP4_CA_RESPONSE_SHAPE_FAILED;
		if (received < 2 || received > sizeof(response))
			goto out;
		report->sw = (unsigned int)response[received - 2] * 256 + response[received - 1];
		report->outcome = JCOP4_CA_SETUP_SW_FAILED;
		if (report->sw != 0x9000)
			goto out;
		report->outcome = JCOP4_CA_RESPONSE_SHAPE_FAILED;
		/* Empty GA template is accepted, but nonce/token or any other payload
		 * stops this candidate. Never silently discard authentication data. */
		if (received != 2 && !(step && received == 4 && response[0] == 0x7C && response[1] == 0))
			goto out;
		if (!step) {
			report->stage = JCOP4_CA_PREPARE;
			report->outcome = JCOP4_CA_CRYPTO_FAILED;
			if (jcop4_ca_build_ga(pending.terminal_public, sizeof(pending.terminal_public),
					    command, sizeof(command), &command_size))
				goto out;
		}
	}
	report->stage = JCOP4_CA_PREPARE;
	report->outcome = JCOP4_CA_CRYPTO_FAILED;
	report->sw = 0;
	if (jcop4_sm_init(&channel, &pending.keys) ||
			jcop4_sm_seal_policy_ex(libctx, &channel, read_header, NULL, 0, 1, 137, header, body, sizeof(body), &body_size, JCOP4_SM_LE_SHORT) ||
			body_size != 13)
		goto out;
	memcpy(command, header, 4);
	command[4] = (unsigned char)body_size;
	memcpy(command + 5, body, body_size);
	command[5 + body_size] = (unsigned char)outer_le;
	command_size = 6 + body_size; /* Case4 short; 256 serializes as00. */
	report->stage = JCOP4_CA_READ;
	report->outcome = JCOP4_CA_TRANSPORT_FAILED;
	received = 0;
	memset(response, 0, sizeof(response));
	report->transport = exchange(context, command, command_size, response, sizeof(response), &received);
	if (report->transport)
		goto out;
	report->outcome = JCOP4_CA_PROTECTED_RESPONSE_FAILED;
	if (received > sizeof(response) || jcop4_sm_open_report_policy_ex(libctx, &channel, response, received, plain, sizeof(plain), &plain_size, &inner_sw, JCOP4_SM_OUTER_9000, NULL))
		goto out;
	report->authenticated_response = 1;
	report->sw = inner_sw;
	report->outcome = JCOP4_CA_INNER_SW_FAILED;
	if (inner_sw != 0x9000)
		goto out;
	/* Fixed D004 comparisons only after MAC/padding and inner SW pass.
	 * No raw bytes, hashes, differing offsets or acceptance of partial data. */
	report->content_size = plain_size;
	report->content_size_equal = plain_size == initial_size;
	if (report->content_size_equal) {
		report->content_first_block_equal = !CRYPTO_memcmp(plain, initial, 16);
		report->content_tail_equal = !CRYPTO_memcmp(plain + 16, initial + 16, initial_size - 16);
	}
	report->outcome = JCOP4_CA_CONTENT_MISMATCH;
	if (plain_size != initial_size || CRYPTO_memcmp(plain, initial, initial_size))
		goto out;
	report->outcome = JCOP4_CA_READ_CONFIRMED;
	if (confirmed)
		memcpy(confirmed, &channel, sizeof(*confirmed));
	result = 0;
out:
	jcop4_ca_pending_clear(&pending);
	jcop4_sm_invalidate(&channel);
	OPENSSL_cleanse(peer, sizeof(peer));
	OPENSSL_cleanse(command, sizeof(command));
	OPENSSL_cleanse(response, sizeof(response));
	OPENSSL_cleanse(body, sizeof(body));
	OPENSSL_cleanse(plain, sizeof(plain));
	return result;
}

/* Standalone default-context compatibility. A retained channel from _ex
 * must continue using its original libctx; this function stores no provider. */
static inline int
jcop4_ca_confirm_d004_session(const unsigned char *initial, size_t initial_size,
		enum jcop4_ca_outer_le outer_le, jcop4_ca_exchange exchange, void *context,
		struct jcop4_ca_probe_report *report, struct jcop4_sm_channel *confirmed)
{
	return jcop4_ca_confirm_d004_session_ex(NULL, initial, initial_size, outer_le, exchange, context, report, confirmed);
}

/* Existing hardware probe never retains a channel or exposes session keys. */
static inline int
jcop4_ca_confirm_d004(const unsigned char *initial, size_t initial_size,
		enum jcop4_ca_outer_le outer_le, jcop4_ca_exchange exchange, void *context,
		struct jcop4_ca_probe_report *report)
{
	return jcop4_ca_confirm_d004_session(initial, initial_size, outer_le, exchange, context, report, NULL);
}

#endif
