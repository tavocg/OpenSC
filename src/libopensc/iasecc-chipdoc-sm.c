/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded anonymous channel transport for the measured ChipDoc profile.
 * Public profile discovery and private typed PIN/signature operations;
 * no generic SM wrapper.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iasecc-chipdoc-sm.h"
#include "iasecc.h"
#include "opensc.h"
#include <limits.h>
#include <stddef.h>
#include <string.h>
#if defined(ENABLE_OPENSSL)
#include <openssl/opensslv.h>
#endif

#if defined(ENABLE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER) && !defined(IASECC_CHIPDOC_NO_CRYPTO)
#include "jcop4-channel-confirmation.h"
#include "jcop4-channel-controls.h"
#include "jcop4-dh-control.h"
#include "sc-ossl-compat.h"
#include <openssl/err.h>

/* Borrowed context identity: sc_context owns providers/libctx and must outlive
 * its card/channel. Never load providers or override its default properties. */
struct chipdoc_provider {
	struct sc_context *context;
	ossl3ctx_t *owner;
	OSSL_LIB_CTX *libctx;
};
static int
chipdoc_provider_matches(struct sc_card *card, const struct chipdoc_provider *provider)
{
	return card && card->ctx && card->ctx == provider->context && card->ctx->ossl3ctx == provider->owner &&
	       provider->owner && provider->owner->libctx == provider->libctx && provider->libctx;
}

struct chipdoc_crypto {
	struct chipdoc_provider provider;
	struct jcop4_sm_channel sm;
	struct sc_card *card;
	struct sc_reader *reader;
	uint64_t generation;
};
struct chipdoc_exchange {
	struct chipdoc_provider provider;
	struct sc_card *card;
	struct iasecc_chipdoc_session *session;
	uint64_t generation;
	struct iasecc_chipdoc_channel_report *report;
	unsigned int step;
};

static void
chipdoc_crypto_clear(void *opaque)
{
	struct chipdoc_crypto *crypto = opaque;
	if (crypto) {
		sc_mem_clear(crypto, sizeof(*crypto));
		sc_mem_secure_free(crypto, sizeof(*crypto));
	}
}

static int
chipdoc_platform_supported(struct sc_card *card)
{
	if (!card || !card->drv_data || !card->ctx || !card->ctx->ossl3ctx || !card->ctx->ossl3ctx->libctx ||
			card->ctx->debug != 0 || card->sm_ctx.sm_mode != SM_MODE_NONE ||
			iasecc_chipdoc_transport(card, IASECC_CHIPDOC_CR_RSA2048) != SC_SUCCESS)
		return SC_ERROR_NOT_SUPPORTED;
	return SC_SUCCESS;
}
static int
chipdoc_platform_ready(struct sc_card *card)
{
	int rv = chipdoc_platform_supported(card);
	if (rv)
		return rv;
	if (card->lock_count < 1)
		return SC_ERROR_NOT_SUPPORTED;
	struct iasecc_private_data *prv = card->drv_data;
	if (prv->chipdoc_transaction.active && !iasecc_chipdoc_transaction_owns(card, prv))
		return SC_ERROR_CARD_RESET;
	return SC_SUCCESS;
}
static int
chipdoc_ready(struct sc_card *card, struct iasecc_private_data **data)
{
	struct iasecc_private_data *prv;
	int rv = chipdoc_platform_ready(card);
	if (rv)
		return rv;
	prv = card->drv_data;
	if (prv->chipdoc_profile != IASECC_CHIPDOC_CR_RSA2048 ||
			prv->chipdoc_session.profile != prv->chipdoc_profile)
		return SC_ERROR_NOT_SUPPORTED;
	*data = prv;
	return SC_SUCCESS;
}

int
iasecc_chipdoc_channel_supported(struct sc_card *card)
{
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	return chipdoc_platform_supported(card);
}

static int
chipdoc_discovery_read(struct sc_card *card, unsigned int offset, unsigned char *out,
		size_t size, unsigned long *flags)
{
	return sc_get_iso7816_driver()->ops->read_binary(card, offset, out, size > 256 ? 256 : size, flags);
}

int
iasecc_chipdoc_detect(struct sc_card *card, struct sc_card_driver *driver)
{
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	struct iasecc_private_data data = {0};
	struct sc_card candidate;
	struct sc_card_operations metadata_ops;
	struct sc_pkcs15_card *p15 = NULL;
	struct sc_pkcs15_object *key;
	struct sc_apdu apdu;
	unsigned char control[256], initial[137], peer[133];
	int matched = 0, rv, marked;

	if (!card || !card->ctx || !card->reader || !card->reader->ops ||
			!card->reader->ops->lock || !card->reader->ops->unlock || !card->reader->ops->reset ||
			card->atr.len != p->atr_len || memcmp(card->atr.value, p->atr, p->atr_len) ||
			(card->max_send_size && card->max_send_size < p->min_send) ||
			(card->max_recv_size && card->max_recv_size < p->min_receive))
		return 0;
	/* Check availability without changing the real card's algorithms, limits,
	 * capabilities, driver or private data on a failed match. */
	candidate = *card;
	candidate.driver = driver;
	candidate.drv_data = &data;
	candidate.caps = SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_ISO7816_PIN_INFO;
	candidate.max_send_size = p->min_send;
	candidate.max_recv_size = p->min_receive;
	if (iasecc_chipdoc_channel_supported(&candidate) != SC_SUCCESS || sc_lock(card) != SC_SUCCESS)
		return 0;

	/* ATR and AID are shared with other personalizations. Require the observed
	 * D004 control structure, size, curve selector and valid public point too.
	 * No reset, authentication, PIN query or secure-channel setup is sent. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0x0C);
	apdu.cla = 0;
	apdu.data = p->aid;
	apdu.datalen = apdu.lc = p->aid_len;
	apdu.resp = control;
	apdu.resplen = sizeof(control);
	apdu.flags = SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	rv = sc_transmit_apdu(card, &apdu);
	if (rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0 || apdu.resplen != 0)
		goto out;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 2, 0);
	apdu.cla = 0;
	apdu.data = (const unsigned char *)"\xD0\x04";
	apdu.datalen = apdu.lc = 2;
	apdu.resp = control;
	apdu.le = apdu.resplen = sizeof(control);
	apdu.flags = SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	rv = sc_transmit_apdu(card, &apdu);
	if (rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0 ||
			apdu.resplen > sizeof(control) || !d004_control_matches_observation(control, apdu.resplen))
		goto out;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0, 0);
	apdu.cla = 0;
	apdu.resp = initial;
	apdu.le = apdu.resplen = sizeof(initial);
	apdu.flags = SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	rv = sc_transmit_apdu(card, &apdu);
	if (rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0 ||
			apdu.resplen != sizeof(initial) || initial[2] != p->curve_selector)
		goto out;
	peer[0] = 4;
	memcpy(peer + 1, initial + 5, sizeof(peer) - 1);
	/* A failed public-point probe must not leave OpenSSL errors for the next
	 * driver, or discard errors which were already present on entry. */
	marked = ERR_set_mark();
	rv = jcop4_p521_public_valid(peer, sizeof(peer));
	if (marked)
		ERR_pop_to_mark();
	else
		ERR_clear_error();
	if (!rv)
		goto out;

	/* Even D004 is not sufficient to claim a shared-ATR card. Bind public
	 * native directories on an isolated view and validate the exact key/PIN
	 * association before selecting this driver. The temporary objects,
	 * caches and routing never become part of the real sc_card. */
	metadata_ops = *sc_get_iso7816_driver()->ops;
	metadata_ops.read_binary = chipdoc_discovery_read;
	candidate.ops = &metadata_ops;
	candidate.type = SC_CARD_TYPE_IASECC_CHIPDOC;
	candidate.cla = 0;
	candidate.lock_count = card->lock_count; /* Borrow the outer reservation. */
	candidate.app_count = -1;
	memset(candidate.app, 0, sizeof(candidate.app));
	data.chipdoc_enabled = 1;
	p15 = sc_pkcs15_card_new();
	if (!p15)
		goto out;
	p15->card = &candidate;
	if (sc_pkcs15_bind_internal(p15, NULL) == SC_SUCCESS)
		matched = iasecc_chipdoc_pkcs15_validate(p15, &key) == SC_SUCCESS;
	sc_pkcs15_unbind(p15);
	sc_free_apps(&candidate);
out:
	sc_mem_clear(control, sizeof(control));
	sc_mem_clear(initial, sizeof(initial));
	sc_mem_clear(peer, sizeof(peer));
	/* The next driver/bind selects its own application. Never reset another
	 * application's authentication state just to undo a discovery SELECT. */
	if (sc_unlock(card) != SC_SUCCESS)
		matched = 0;
	return matched;
}

int
iasecc_chipdoc_channel_pin_status(struct sc_card *card, int *logged_in)
{
	if (logged_in)
		*logged_in = SC_PIN_STATE_UNKNOWN;
	if (!logged_in)
		return SC_ERROR_INVALID_ARGUMENTS;
	int rv = iasecc_chipdoc_channel_supported(card);
	if (rv)
		return rv;
	struct iasecc_private_data *prv = card->drv_data;
	if (prv->chipdoc_recovery_required)
		return SC_ERROR_CARD_RESET;
	if (!prv->chipdoc_transaction.active) {
		if (prv->chipdoc_session.phase != IASECC_CHIPDOC_INACTIVE || prv->chipdoc_session.channel)
			return SC_ERROR_SM_SESSION_ALREADY_ACTIVE;
		*logged_in = SC_PIN_STATE_LOGGED_OUT;
		return SC_SUCCESS;
	}
	if (!iasecc_chipdoc_transaction_owns(card, prv) || prv->chipdoc_profile != IASECC_CHIPDOC_CR_RSA2048 ||
			prv->chipdoc_session.profile != prv->chipdoc_profile)
		return SC_ERROR_CARD_RESET;
	struct chipdoc_crypto *crypto = prv->chipdoc_session.channel;
	if (!crypto || prv->chipdoc_session.clear_channel != chipdoc_crypto_clear || crypto->card != card ||
			crypto->reader != card->reader || crypto->generation != prv->chipdoc_session.generation ||
			!chipdoc_provider_matches(card, &crypto->provider) || crypto->sm.phase != JCOP4_SM_IDLE) {
		iasecc_chipdoc_invalidate_card(card);
		return SC_ERROR_CARD_RESET;
	}
	unsigned int counter = prv->chipdoc_session.phase == IASECC_CHIPDOC_LOGGED_IN ? 8 : prv->chipdoc_session.phase == IASECC_CHIPDOC_APPLICATION ? 10
									    : prv->chipdoc_session.phase == IASECC_CHIPDOC_MSE			     ? 12
																		     : 0;
	unsigned char expected[16] = {0};
	expected[15] = counter;
	if (!counter || CRYPTO_memcmp(crypto->sm.keys.ssc, expected, sizeof(expected))) {
		iasecc_chipdoc_invalidate_card(card);
		return SC_ERROR_CARD_RESET;
	}
	*logged_in = SC_PIN_STATE_LOGGED_IN;
	return SC_SUCCESS;
}

/* Only the three known setup commands, through normal OpenSC validation and
 * recursive transaction locking. Never dispatch directly to reader->transmit. */
static int
chipdoc_setup_exchange(void *opaque, const unsigned char *wire, size_t size,
		unsigned char *response, size_t capacity, size_t *received)
{
	struct chipdoc_exchange *x = opaque;
	struct iasecc_private_data *prv = NULL;
	sc_apdu_t apdu;
	int rv, cse;
	static const unsigned char mse[] = {0, 0x22, 0x41, 0xA4, 12, 0x80, 10, 4, 0, 0x7F, 0, 7, 2, 2, 3, 2, 2};
	if (!received)
		return SC_ERROR_INVALID_ARGUMENTS;
	*received = 0;
	if (!x || !wire || !response || capacity != 258 || chipdoc_ready(x->card, &prv) ||
			!chipdoc_provider_matches(x->card, &x->provider) ||
			&prv->chipdoc_session != x->session || x->session->phase != IASECC_CHIPDOC_PREPARED ||
			x->session->generation != x->generation || x->step >= 3)
		return SC_ERROR_NOT_ALLOWED;
	if (!x->step) {
		if (size != sizeof(mse) || memcmp(wire, mse, sizeof(mse)))
			return SC_ERROR_NOT_ALLOWED;
		cse = SC_APDU_CASE_3_SHORT;
	} else if (x->step == 1) {
		if (size != 144 || memcmp(wire, "\x10\x86\0\0\x8b\x7c\x81\x88\x80\x81\x85", 11) ||
				!jcop4_p521_public_valid(wire + 11, 133))
			return SC_ERROR_NOT_ALLOWED;
		cse = SC_APDU_CASE_3_SHORT;
	} else {
		if (size != 19 || memcmp(wire, "\x0c\xb0\0\0\x0d\x97\x01\x89\x8e\x08", 10) || wire[18])
			return SC_ERROR_NOT_ALLOWED;
		cse = SC_APDU_CASE_4_SHORT;
	}
	sc_format_apdu(x->card, &apdu, cse, wire[1], wire[2], wire[3]);
	apdu.cla = wire[0];
	apdu.data = wire + 5;
	apdu.lc = apdu.datalen = wire[4];
	apdu.le = x->step == 2 ? 256 : 0;
	apdu.resp = response;
	apdu.resplen = capacity - 2;
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	x->step++;
	x->report->commands++;
	x->report->reset_required = 1;
	rv = sc_transmit_apdu(x->card, &apdu);
	x->report->transport = rv;
	if (rv < 0)
		return rv;
	if (!chipdoc_provider_matches(x->card, &x->provider) ||
			x->session->generation != x->generation || x->session->phase != IASECC_CHIPDOC_PREPARED)
		return SC_ERROR_CARD_RESET;
	if (apdu.resplen > capacity - 2)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	response[apdu.resplen] = apdu.sw1;
	response[apdu.resplen + 1] = apdu.sw2;
	*received = apdu.resplen + 2;
	return SC_SUCCESS;
}

int
iasecc_chipdoc_channel_open(struct sc_card *card, const unsigned char *initial,
		size_t size, struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	struct chipdoc_crypto *crypto = NULL;
	struct jcop4_ca_probe_report confirmed;
	struct chipdoc_exchange x;
	int rv;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (card && card->drv_data)
		report->reset_required = ((struct iasecc_private_data *)card->drv_data)->chipdoc_session.channel != NULL;
	rv = chipdoc_ready(card, &prv);
	if (rv)
		return rv;
	if (prv->chipdoc_session.phase != IASECC_CHIPDOC_PREPARED ||
			prv->chipdoc_session.channel || prv->chipdoc_session.clear_channel)
		return SC_ERROR_SM_SESSION_ALREADY_ACTIVE;
	crypto = sc_mem_secure_alloc(sizeof(*crypto));
	if (!crypto)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(crypto, 0, sizeof(*crypto));
	crypto->provider = (struct chipdoc_provider){card->ctx, card->ctx->ossl3ctx, card->ctx->ossl3ctx->libctx};
	x = (struct chipdoc_exchange){crypto->provider, card, &prv->chipdoc_session, prv->chipdoc_session.generation, report, 0};
	rv = jcop4_ca_confirm_d004_session_ex(crypto->provider.libctx, initial, size, JCOP4_CA_LE_SHORT_MAX,
			chipdoc_setup_exchange, &x, &confirmed, &crypto->sm);
	report->authenticated = confirmed.authenticated_response;
	if (confirmed.authenticated_response)
		report->sw = confirmed.sw;
	if (rv) {
		rv = confirmed.transport < 0 ? confirmed.transport : SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto fail;
	}
	if (!chipdoc_provider_matches(card, &crypto->provider) ||
			prv->chipdoc_session.generation != x.generation || crypto->sm.phase != JCOP4_SM_IDLE || x.step != 3) {
		rv = SC_ERROR_CARD_RESET;
		goto fail;
	}
	crypto->card = card;
	crypto->reader = card->reader;
	crypto->generation = x.generation;
	rv = iasecc_chipdoc_attach(&prv->chipdoc_session, x.generation, crypto, chipdoc_crypto_clear);
	if (rv)
		goto fail;
	return SC_SUCCESS;
fail:
	chipdoc_crypto_clear(crypto);
	iasecc_chipdoc_invalidate_card(card);
	return rv;
}

int
iasecc_chipdoc_channel_select_mf(struct sc_card *card,
		enum iasecc_chipdoc_mf_encoding encoding, struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	struct chipdoc_crypto *crypto;
	unsigned char header[4], body[33], response[293], plain[256];
	const unsigned char logical[4] = {0, 0xA4, 0, 0}, mf[2] = {0x3F, 0};
	size_t written, size, plain_size;
	unsigned int sw;
	uint64_t generation;
	sc_apdu_t apdu;
	struct jcop4_sm_decode_report decoded;
	int rv, result;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (card && card->drv_data)
		report->reset_required = ((struct iasecc_private_data *)card->drv_data)->chipdoc_session.channel != NULL;
	if (encoding != IASECC_CHIPDOC_MF_SHORT && encoding != IASECC_CHIPDOC_MF_EXTENDED)
		return SC_ERROR_INVALID_ARGUMENTS;
	rv = chipdoc_ready(card, &prv);
	if (rv) {
		iasecc_chipdoc_invalidate_card(card);
		return rv;
	}
	if (prv->chipdoc_session.phase != IASECC_CHIPDOC_CHANNEL || !prv->chipdoc_session.channel ||
			prv->chipdoc_session.clear_channel != chipdoc_crypto_clear)
		return SC_ERROR_SM_NOT_INITIALIZED;
	crypto = prv->chipdoc_session.channel;
	generation = prv->chipdoc_session.generation;
	if (!chipdoc_provider_matches(card, &crypto->provider) || crypto->card != card ||
			crypto->reader != card->reader || crypto->generation != prv->chipdoc_session.generation ||
			crypto->sm.phase != JCOP4_SM_IDLE) {
		iasecc_chipdoc_invalidate_card(card);
		return SC_ERROR_CARD_RESET;
	}
	result = SC_ERROR_SM_ENCRYPT_FAILED;
	if (jcop4_sm_seal_policy_ex(crypto->provider.libctx, &crypto->sm, logical, mf, 2, 1, 256, header, body, sizeof(body), &written,
			    encoding == IASECC_CHIPDOC_MF_EXTENDED ? JCOP4_SM_LE_TWO_BYTE_256 : JCOP4_SM_LE_SHORT))
		goto out;
	if (written != (encoding == IASECC_CHIPDOC_MF_EXTENDED ? 33u : 32u))
		goto out;
	sc_format_apdu(card, &apdu, encoding == IASECC_CHIPDOC_MF_EXTENDED ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	apdu.cla = header[0];
	apdu.data = body;
	apdu.lc = apdu.datalen = written;
	apdu.le = encoding == IASECC_CHIPDOC_MF_EXTENDED ? 291 : 256;
	apdu.resplen = apdu.le;
	apdu.resp = response;
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	report->commands = 1;
	report->reset_required = 1;
	rv = sc_transmit_apdu(card, &apdu);
	report->transport = rv;
	result = rv;
	if (rv < 0)
		goto out;
	/* A reset hook may have freed crypto during normal transport. Check the
	 * session ownership/generation BEFORE touching that context again. */
	if (prv->chipdoc_session.channel != crypto || prv->chipdoc_session.generation != generation ||
			!chipdoc_provider_matches(card, &crypto->provider)) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	result = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resplen > sizeof(response) - 2 || apdu.resplen > apdu.le)
		goto out;
	size = apdu.resplen;
	response[size++] = apdu.sw1;
	response[size++] = apdu.sw2;
	result = SC_ERROR_SM_AUTHENTICATION_FAILED;
	if (jcop4_sm_open_report_policy_ex(crypto->provider.libctx, &crypto->sm, response, size, plain, sizeof(plain), &plain_size, &sw, JCOP4_SM_OUTER_9000, &decoded))
		goto out;
	report->authenticated = 1;
	report->sw = sw;
	if (sw != 0x9000) {
		result = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		goto out;
	}
	if (jcop4_sm_mf_control(plain, plain_size)) {
		result = SC_ERROR_INVALID_DATA;
		goto out;
	}
	result = iasecc_chipdoc_record(&prv->chipdoc_session, crypto->generation, IASECC_CHIPDOC_RESPONSE_MF, sw, 0, 0);
	/* SELECT MF changed the physical selection. Do not keep an ADF/D004 cache
	 * from bootstrap or pretend this decoder populated a full sc_file object. */
	if (!result)
		sc_invalidate_cache(card);
out:
	sc_mem_clear(header, sizeof(header));
	sc_mem_clear(body, sizeof(body));
	sc_mem_clear(response, sizeof(response));
	sc_mem_clear(plain, sizeof(plain));
	if (result)
		iasecc_chipdoc_invalidate_card(card);
	return result;
}
/* Bootstrap uses only the three measured plain commands, with no library
 * selection/read helpers that could split, retry or silently reuse a cache. */
struct chipdoc_bootstrap {
	struct sc_card *card;
	struct sc_reader *reader;
	struct iasecc_private_data *prv;
	struct chipdoc_provider provider;
	uint64_t generation;
	struct iasecc_chipdoc_bootstrap_report *report;
};
static int
chipdoc_bootstrap_exchange(struct chipdoc_bootstrap *x, struct sc_apdu *apdu)
{
	int rv;
	struct iasecc_chipdoc_session *session = &x->prv->chipdoc_session;
	if (chipdoc_platform_ready(x->card) || !chipdoc_provider_matches(x->card, &x->provider) ||
			x->card->reader != x->reader || x->card->drv_data != x->prv ||
			session->phase != IASECC_CHIPDOC_BOOTSTRAPPING || session->generation != x->generation)
		return SC_ERROR_CARD_RESET;
	apdu->cla = 0;
	apdu->flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	x->report->channel.commands++;
	x->report->channel.reset_required = 1;
	rv = sc_transmit_apdu(x->card, apdu);
	x->report->channel.transport = rv;
	if (rv < 0)
		return rv;
	if (chipdoc_platform_ready(x->card) || !chipdoc_provider_matches(x->card, &x->provider) ||
			x->card->reader != x->reader || x->card->drv_data != x->prv ||
			session->phase != IASECC_CHIPDOC_BOOTSTRAPPING || session->generation != x->generation)
		return SC_ERROR_CARD_RESET;
	if (apdu->sw1 == 0x90 && apdu->sw2 == 0)
		return SC_SUCCESS;
	rv = sc_check_sw(x->card, apdu->sw1, apdu->sw2);
	return rv < 0 ? rv : SC_ERROR_UNKNOWN_DATA_RECEIVED;
}

int
iasecc_chipdoc_channel_bootstrap(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_bootstrap_report *report)
{
	struct sc_card *card = p15 ? p15->card : NULL;
	struct iasecc_private_data *prv;
	struct sc_aid aid;
	struct iasecc_chipdoc_key_metadata key_metadata;
	struct iasecc_chipdoc_metadata metadata;
	const struct iasecc_chipdoc_profile *profile = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	struct iasecc_chipdoc_channel_report channel;
	struct chipdoc_bootstrap x;
	struct sc_apdu apdu;
	unsigned char control[256] = {0}, initial[137] = {0}, peer[133] = {0};
	int rv;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	/* This API is internal to iasecc; never interpret another driver's data. */
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->channel.reset_required = prv->chipdoc_session.channel != NULL;
	rv = chipdoc_platform_ready(card);
	if (rv)
		return rv;
	if (prv->chipdoc_session.phase != IASECC_CHIPDOC_INACTIVE || prv->chipdoc_session.profile ||
			prv->chipdoc_session.channel || prv->chipdoc_session.clear_channel)
		return SC_ERROR_SM_SESSION_ALREADY_ACTIVE;
	if (prv->chipdoc_profile != IASECC_CHIPDOC_NONE && prv->chipdoc_profile != IASECC_CHIPDOC_CR_RSA2048)
		return SC_ERROR_NOT_SUPPORTED;
	rv = iasecc_chipdoc_pkcs15_key(p15, key, &aid, &key_metadata);
	if (rv)
		return rv;
	rv = iasecc_chipdoc_begin_bootstrap(&prv->chipdoc_session, IASECC_CHIPDOC_CR_RSA2048);
	if (rv)
		return rv;
	x = (struct chipdoc_bootstrap){
			card, card->reader, prv,
			{card->ctx, card->ctx->ossl3ctx, card->ctx->ossl3ctx->libctx},
			prv->chipdoc_session.generation, report
	       };
	sc_invalidate_cache(card);
	report->stage = IASECC_CHIPDOC_BOOTSTRAP_APPLICATION;
	/* SELECT AID, P2=0C, CASE3 and no Le as in the successful helper. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0x0C);
	apdu.data = aid.value;
	apdu.datalen = apdu.lc = aid.len;
	apdu.resp = control;
	apdu.resplen = sizeof(control);
	rv = chipdoc_bootstrap_exchange(&x, &apdu);
	if (rv)
		goto out;
	if (apdu.resplen) {
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto out;
	}
	report->stage = IASECC_CHIPDOC_BOOTSTRAP_CONTROL;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 2, 0);
	apdu.data = (const unsigned char *)"\xD0\x04";
	apdu.datalen = apdu.lc = 2;
	apdu.resp = control;
	apdu.le = apdu.resplen = sizeof(control);
	rv = chipdoc_bootstrap_exchange(&x, &apdu);
	if (rv)
		goto out;
	if (apdu.resplen > sizeof(control) || !d004_control_matches_observation(control, apdu.resplen)) {
		rv = SC_ERROR_INVALID_DATA;
		goto out;
	}
	report->stage = IASECC_CHIPDOC_BOOTSTRAP_READ;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0, 0);
	apdu.resp = initial;
	apdu.le = apdu.resplen = sizeof(initial);
	rv = chipdoc_bootstrap_exchange(&x, &apdu);
	if (rv)
		goto out;
	if (apdu.resplen != sizeof(initial) || initial[2] != profile->curve_selector) {
		rv = SC_ERROR_INVALID_DATA;
		goto out;
	}
	peer[0] = 4;
	memcpy(peer + 1, initial + 5, 132);
	if (!jcop4_p521_public_valid(peer, sizeof(peer))) {
		rv = SC_ERROR_INVALID_DATA;
		goto out;
	}
	/* Permanent binding follows live D004 validation plus native PKCS#15
	 * key/PIN association. Candidate metadata is not a MAC or card identity. */
	prv->chipdoc_profile = IASECC_CHIPDOC_CR_RSA2048;
	iasecc_chipdoc_invalidate_card(card);
	metadata = (struct iasecc_chipdoc_metadata){SC_ALGORITHM_RSA, key_metadata.reference,
			key_metadata.bits, key_metadata.pin_reference, 0xD004, sizeof(initial), initial[2], 1, 1};
	report->stage = IASECC_CHIPDOC_BOOTSTRAP_PREPARE;
	rv = iasecc_chipdoc_prepare(&prv->chipdoc_session, card, &aid, &metadata);
	if (rv)
		goto out;
	report->stage = IASECC_CHIPDOC_BOOTSTRAP_CHANNEL;
	rv = iasecc_chipdoc_channel_open(card, initial, sizeof(initial), &channel);
	report->channel.commands += channel.commands;
	report->channel.transport = channel.transport;
	report->channel.authenticated = channel.authenticated;
	report->channel.sw = channel.sw;
	report->channel.reset_required |= channel.reset_required;
out:
	sc_mem_clear(control, sizeof(control));
	sc_mem_clear(initial, sizeof(initial));
	sc_mem_clear(peer, sizeof(peer));
	if (rv)
		iasecc_chipdoc_invalidate_card(card);
	return rv;
}

int
iasecc_chipdoc_transaction_begin(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_transaction_report *report)
{
	struct sc_card *card = p15 ? p15->card : NULL;
	struct iasecc_private_data *prv;
	struct sc_aid aid;
	struct iasecc_chipdoc_key_metadata metadata;
	struct iasecc_chipdoc_bootstrap_report bootstrap;
	struct iasecc_chipdoc_channel_report mf;
	struct iasecc_chipdoc_transaction_report closed;
	int rv, before;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->reset_required = prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required;
	rv = chipdoc_platform_supported(card);
	if (rv)
		return rv;
	if (prv->chipdoc_transaction.active || prv->chipdoc_session.profile || prv->chipdoc_session.channel ||
			prv->chipdoc_session.phase != IASECC_CHIPDOC_INACTIVE)
		return SC_ERROR_SM_SESSION_ALREADY_ACTIVE;
	if (prv->chipdoc_recovery_required)
		return SC_ERROR_CARD_RESET;
	if (!card->reader->ops || !card->reader->ops->lock || !card->reader->ops->unlock || !card->reader->ops->reset ||
			!card->ops || !card->ops->card_reader_lock_obtained || card->lock_count < 0 || card->lock_count == INT_MAX)
		return SC_ERROR_NOT_SUPPORTED;
	rv = iasecc_chipdoc_pkcs15_key(p15, key, &aid, &metadata);
	if (rv)
		return rv;
	struct iasecc_chipdoc_pkcs15_operation operation;
	rv = iasecc_chipdoc_pkcs15_operation(p15, key, &operation);
	if (rv)
		return rv;
	if (p15->opts.use_pin_cache)
		return SC_ERROR_NOT_ALLOWED;
	before = card->lock_count;
	report->stage = IASECC_CHIPDOC_TX_LOCK;
	rv = sc_lock(card);
	report->lock_result = rv;
	if (rv) {
		/* sc_lock can report a mutex-release error AFTER incrementing its
		 * count. That error is not proof of an owned usable transaction. */
		if (card->lock_count != before) {
			prv->chipdoc_transaction = (struct iasecc_chipdoc_transaction){.card = card, .reader = card->reader, .context = card->ctx, .active = 1, .lost = 1};
			prv->chipdoc_recovery_required = report->reset_required = 1;
			report->lock_held = card->lock_count > 0;
			iasecc_chipdoc_invalidate_card(card);
		}
		return rv;
	}
	/* No foreign mutation of reader/context/driver is permitted by the API
	 * contract; transaction ownership below also detects later replacement. */
	prv->chipdoc_transaction = (struct iasecc_chipdoc_transaction){.card = card, .reader = card->reader, .context = card->ctx, .active = 1, .owned_lock = 1, .pin = metadata.pin};
	report->lock_held = 1;
	if (card->lock_count != before + 1) {
		prv->chipdoc_transaction.lost = 1;
		prv->chipdoc_transaction.owned_lock = 0;
		prv->chipdoc_recovery_required = 1;
		rv = SC_ERROR_CARD_RESET;
		goto fail;
	}
	iasecc_chipdoc_invalidate_card(card);
	report->stage = IASECC_CHIPDOC_TX_RESET;
	report->initial_reset_attempted = 1;
	rv = sc_reset(card, 0);
	report->initial_reset_result = rv;
	if (rv) {
		prv->chipdoc_recovery_required = 1;
		goto fail;
	} /* no reset retry */
	prv->chipdoc_transaction.reset_required = report->reset_required = 1;
	if (!iasecc_chipdoc_transaction_owns(card, prv)) {
		rv = SC_ERROR_CARD_RESET;
		goto fail;
	}
	report->stage = IASECC_CHIPDOC_TX_BOOTSTRAP;
	rv = iasecc_chipdoc_channel_bootstrap(p15, key, &bootstrap);
	report->commands = bootstrap.channel.commands;
	report->bootstrap_stage = bootstrap.stage;
	if (rv)
		goto fail;
	report->stage = IASECC_CHIPDOC_TX_MF;
	rv = iasecc_chipdoc_channel_select_mf(card, IASECC_CHIPDOC_MF_SHORT, &mf);
	report->commands += mf.commands;
	if (rv)
		goto fail;
	report->stage = IASECC_CHIPDOC_TX_READY;
	return SC_SUCCESS;
fail:
	(void)iasecc_chipdoc_transaction_close(card, &closed);
	report->close_attempted = closed.close_attempted;
	report->final_reset_attempted = closed.final_reset_attempted;
	report->final_reset_result = closed.final_reset_result;
	report->unlock_attempted = closed.unlock_attempted;
	report->unlock_result = closed.unlock_result;
	report->complete = closed.complete;
	report->reset_required = closed.reset_required;
	report->lock_held = 0;
	return rv;
}

int
iasecc_chipdoc_channel_query_pin(struct sc_card *card, unsigned int reference,
		int *tries_left, struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	struct chipdoc_crypto *crypto;
	unsigned char header[4], body[10], response[258], plain[256];
	const unsigned char query[4] = {0, 0x20, 0, 1};
	size_t written = 0, size, plain_size;
	unsigned int sw;
	uint64_t generation;
	struct sc_apdu apdu;
	struct jcop4_sm_decode_report decoded;
	int rv, result = SC_ERROR_SM_ENCRYPT_FAILED;
	if (tries_left)
		*tries_left = -1;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	if (card->drv_data)
		report->reset_required = (((struct iasecc_private_data *)card->drv_data)->chipdoc_session.channel != NULL ||
					  ((struct iasecc_private_data *)card->drv_data)->chipdoc_transaction.active ||
					  ((struct iasecc_private_data *)card->drv_data)->chipdoc_recovery_required);
	if (!tries_left || reference != 1)
		return SC_ERROR_INVALID_ARGUMENTS;
	rv = chipdoc_ready(card, &prv);
	if (rv) {
		iasecc_chipdoc_invalidate_card(card);
		return rv;
	}
	if (!iasecc_chipdoc_transaction_owns(card, prv))
		return SC_ERROR_NOT_ALLOWED;
	if (prv->chipdoc_session.phase != IASECC_CHIPDOC_MF || !prv->chipdoc_session.channel ||
			prv->chipdoc_session.clear_channel != chipdoc_crypto_clear)
		return SC_ERROR_SM_NOT_INITIALIZED;
	crypto = prv->chipdoc_session.channel;
	generation = prv->chipdoc_session.generation;
	if (!chipdoc_provider_matches(card, &crypto->provider) || crypto->card != card || crypto->reader != card->reader ||
			crypto->generation != generation || crypto->sm.phase != JCOP4_SM_IDLE) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	/* Empty inner VERIFY: MAC only, no credential/DO87/DO97. */
	if (jcop4_sm_seal_policy_ex(crypto->provider.libctx, &crypto->sm, query, NULL, 0, 0, 0,
			    header, body, sizeof(body), &written, JCOP4_SM_LE_SHORT) ||
			written != sizeof(body))
		goto out;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x20, 0, 1);
	apdu.cla = header[0];
	apdu.data = body;
	apdu.lc = apdu.datalen = written;
	apdu.le = 256;
	apdu.resp = response;
	apdu.resplen = 256;
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	report->commands = 1;
	report->reset_required = 1;
	rv = sc_transmit_apdu(card, &apdu);
	report->transport = rv;
	result = rv;
	if (rv < 0)
		goto out;
	if (prv->chipdoc_session.channel != crypto || prv->chipdoc_session.generation != generation ||
			!iasecc_chipdoc_transaction_owns(card, prv) || !chipdoc_provider_matches(card, &crypto->provider)) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	result = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resplen > 256)
		goto out;
	size = apdu.resplen;
	response[size++] = apdu.sw1;
	response[size++] = apdu.sw2;
	result = SC_ERROR_SM_AUTHENTICATION_FAILED;
	if (jcop4_sm_open_report_policy_ex(crypto->provider.libctx, &crypto->sm, response, size, plain,
			    sizeof(plain), &plain_size, &sw, JCOP4_SM_OUTER_9000_OR_MATCHING_63CX, &decoded))
		goto out;
	report->authenticated = 1;
	report->sw = sw;
	result = SC_ERROR_INVALID_DATA;
	if (plain_size)
		goto out;
	result = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	if ((sw & 0xFFF0) != 0x63C0)
		goto out;
	*tries_left = sw & 15;
	if (!*tries_left) {
		result = SC_ERROR_AUTH_METHOD_BLOCKED;
		goto out;
	}
	result = iasecc_chipdoc_record(&prv->chipdoc_session, generation, IASECC_CHIPDOC_RESPONSE_QUERY, sw, 0, 0);
out:
	sc_mem_clear(header, sizeof(header));
	sc_mem_clear(body, sizeof(body));
	sc_mem_clear(response, sizeof(response));
	sc_mem_clear(plain, sizeof(plain));
	if (result)
		iasecc_chipdoc_invalidate_card(card);
	return result;
}

int
iasecc_chipdoc_channel_verify_pin(struct sc_card *card, const struct sc_pin_cmd_data *data,
		int *tries_left, struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	struct chipdoc_crypto *crypto;
	const unsigned char verify[4] = {0, 0x20, 0, 1}, expected_ssc[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6};
	unsigned char header[4], body[29], response[258], plain[256];
	size_t written = 0, size, plain_size;
	unsigned int sw;
	uint64_t generation;
	struct sc_apdu apdu;
	struct jcop4_sm_decode_report decoded;
	int rv, result = SC_ERROR_SM_ENCRYPT_FAILED;
	if (tries_left)
		*tries_left = -1;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->reset_required = prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required;
	if (!data || !tries_left)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (data->cmd != SC_PIN_CMD_VERIFY)
		return SC_ERROR_NOT_SUPPORTED;
	if (data->flags || data->pin_type != SC_AC_CHV || data->pin_reference != 1 || data->puk_reference ||
			data->apdu || data->pin2.data || data->pin2.len || data->pin1.encoding != SC_PIN_ENCODING_ASCII)
		return SC_ERROR_INVALID_ARGUMENTS;
	rv = chipdoc_ready(card, &prv);
	if (rv) {
		iasecc_chipdoc_invalidate_card(card);
		return rv;
	}
	if (!iasecc_chipdoc_transaction_owns(card, prv))
		return SC_ERROR_NOT_ALLOWED;
	if (prv->chipdoc_transaction.pin.minimum != 6 || prv->chipdoc_transaction.pin.maximum != 14 ||
			prv->chipdoc_transaction.pin.format != SC_PKCS15_PIN_TYPE_UTF8 ||
			prv->chipdoc_transaction.pin.flags != (SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED))
		return SC_ERROR_NOT_SUPPORTED;
	if ((data->pin1.min_length && data->pin1.min_length != 6) ||
			(data->pin1.max_length && data->pin1.max_length != 14))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!data->pin1.data || data->pin1.len < 6 || data->pin1.len > 14)
		return SC_ERROR_INVALID_PIN_LENGTH;
	if (prv->chipdoc_session.phase != IASECC_CHIPDOC_PIN_AVAILABLE || !prv->chipdoc_session.channel ||
			prv->chipdoc_session.clear_channel != chipdoc_crypto_clear)
		return SC_ERROR_SM_NOT_INITIALIZED;
	crypto = prv->chipdoc_session.channel;
	generation = prv->chipdoc_session.generation;
	if (!chipdoc_provider_matches(card, &crypto->provider) || crypto->card != card || crypto->reader != card->reader ||
			crypto->generation != generation || crypto->sm.phase != JCOP4_SM_IDLE ||
			CRYPTO_memcmp(crypto->sm.keys.ssc, expected_ssc, sizeof(expected_ssc))) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	/* No normalization/truncation/hash/credential padding or persistent copy.
	 * The caller's borrowed bytes are read only after all session checks. */
	for (size_t i = 0; i < data->pin1.len; i++)
		if (data->pin1.data[i] < 0x20 || data->pin1.data[i] > 0x7E)
			return SC_ERROR_INVALID_ARGUMENTS;
	if (jcop4_sm_seal_policy_ex(crypto->provider.libctx, &crypto->sm, verify, data->pin1.data, data->pin1.len,
			    0, 0, header, body, sizeof(body), &written, JCOP4_SM_LE_SHORT) ||
			written != sizeof(body))
		goto out;
	/* Only encrypted DO87 and MAC reach the transport. Seal already cleans
	 * its plaintext/padding temporary; caller remains owner of its input. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x20, 0, 1);
	apdu.cla = header[0];
	apdu.data = body;
	apdu.lc = apdu.datalen = written;
	apdu.le = 256;
	apdu.resp = response;
	apdu.resplen = 256;
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	report->commands = 1;
	report->reset_required = 1;
	rv = sc_transmit_apdu(card, &apdu);
	report->transport = rv;
	result = rv;
	if (rv < 0)
		goto out;
	if (prv->chipdoc_session.channel != crypto || prv->chipdoc_session.generation != generation ||
			!iasecc_chipdoc_transaction_owns(card, prv) || !chipdoc_provider_matches(card, &crypto->provider)) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	result = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resplen > 256)
		goto out;
	size = apdu.resplen;
	response[size++] = apdu.sw1;
	response[size++] = apdu.sw2;
	result = SC_ERROR_SM_AUTHENTICATION_FAILED;
	if (jcop4_sm_open_report_policy_ex(crypto->provider.libctx, &crypto->sm, response, size, plain,
			    sizeof(plain), &plain_size, &sw, JCOP4_SM_OUTER_9000_OR_MATCHING_63CX, &decoded))
		goto out;
	report->authenticated = 1;
	report->sw = sw;
	result = SC_ERROR_INVALID_DATA;
	if (plain_size)
		goto out;
	if ((sw & 0xFFF0) == 0x63C0) {
		*tries_left = sw & 15;
		result = *tries_left ? SC_ERROR_PIN_CODE_INCORRECT : SC_ERROR_AUTH_METHOD_BLOCKED;
		goto out;
	}
	if (sw == 0x6983) {
		result = SC_ERROR_AUTH_METHOD_BLOCKED;
		goto out;
	}
	if (sw == 0x6982) {
		result = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		goto out;
	}
	if (sw != 0x9000) {
		result = SC_ERROR_CARD_CMD_FAILED;
		goto out;
	}
	result = iasecc_chipdoc_record(&prv->chipdoc_session, generation, IASECC_CHIPDOC_RESPONSE_LOGIN, sw, 0, 0);
out:
	sc_mem_clear(header, sizeof(header));
	sc_mem_clear(body, sizeof(body));
	sc_mem_clear(response, sizeof(response));
	sc_mem_clear(plain, sizeof(plain));
	if (result)
		iasecc_chipdoc_invalidate_card(card);
	return result;
}

/* Managed signing operations only. A phase mismatch is a local error; a
 * stale provider/SSC/owner is an invalid session, never an invitation to retry. */
static int
chipdoc_signing_ready(struct sc_card *card, enum iasecc_chipdoc_phase phase,
		unsigned int counter, struct iasecc_private_data **data)
{
	struct iasecc_private_data *prv = NULL;
	unsigned char expected[16] = {0};
	int rv;
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	rv = chipdoc_ready(card, &prv);
	if (rv) {
		iasecc_chipdoc_invalidate_card(card);
		return rv;
	}
	if (!iasecc_chipdoc_transaction_owns(card, prv))
		return SC_ERROR_NOT_ALLOWED;
	if (prv->chipdoc_session.phase != phase || !prv->chipdoc_session.channel ||
			prv->chipdoc_session.clear_channel != chipdoc_crypto_clear)
		return SC_ERROR_SM_NOT_INITIALIZED;
	struct chipdoc_crypto *crypto = prv->chipdoc_session.channel;
	expected[15] = counter;
	if (!chipdoc_provider_matches(card, &crypto->provider) || crypto->card != card || crypto->reader != card->reader ||
			crypto->generation != prv->chipdoc_session.generation || crypto->sm.phase != JCOP4_SM_IDLE ||
			CRYPTO_memcmp(crypto->sm.keys.ssc, expected, sizeof(expected))) {
		iasecc_chipdoc_invalidate_card(card);
		return SC_ERROR_CARD_RESET;
	}
	*data = prv;
	return SC_SUCCESS;
}

/* Three fixed call sites below; not an arbitrary-command or plaintext API. */
static int
chipdoc_signature_exchange(struct sc_card *card, enum iasecc_chipdoc_phase phase,
		unsigned int counter, const unsigned char command[4], const unsigned char *data, size_t data_size,
		int extended, unsigned char *plain, size_t capacity, size_t *plain_size,
		struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	struct chipdoc_crypto *crypto;
	unsigned char header[4], body[65], response[293];
	size_t written = 0, size;
	unsigned int sw;
	uint64_t generation;
	struct sc_apdu apdu;
	struct jcop4_sm_decode_report decoded;
	int rv, result = SC_ERROR_SM_ENCRYPT_FAILED;
	report->authenticated = 0;
	report->sw = 0;
	*plain_size = 0;
	rv = chipdoc_signing_ready(card, phase, counter, &prv);
	if (rv)
		return rv;
	crypto = prv->chipdoc_session.channel;
	generation = prv->chipdoc_session.generation;
	if (jcop4_sm_seal_policy_ex(crypto->provider.libctx, &crypto->sm, command, data, data_size,
			    extended, extended ? 256 : 0, header, body, sizeof(body), &written,
			    extended ? JCOP4_SM_LE_TWO_BYTE_256 : JCOP4_SM_LE_SHORT) ||
			written != (extended ? 65u : 29u))
		goto out;
	sc_format_apdu(card, &apdu, extended ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT,
			command[1], command[2], command[3]);
	apdu.cla = header[0];
	apdu.data = body;
	apdu.lc = apdu.datalen = written;
	apdu.le = extended ? 291 : 256;
	apdu.resp = response;
	apdu.resplen = apdu.le;
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;
	report->commands++;
	report->reset_required = 1;
	rv = sc_transmit_apdu(card, &apdu);
	report->transport = rv;
	result = rv;
	if (rv < 0)
		goto out;
	/* Callback may invalidate/free crypto; compare owner/generation FIRST. */
	if (prv->chipdoc_session.channel != crypto || prv->chipdoc_session.generation != generation ||
			!iasecc_chipdoc_transaction_owns(card, prv) || !chipdoc_provider_matches(card, &crypto->provider)) {
		result = SC_ERROR_CARD_RESET;
		goto out;
	}
	result = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resplen > apdu.le)
		goto out;
	size = apdu.resplen;
	response[size++] = apdu.sw1;
	response[size++] = apdu.sw2;
	result = SC_ERROR_SM_AUTHENTICATION_FAILED;
	/* Retain only the already observed status-only PSO6A82 error policy. It
	 * never authorizes a continuation, successful result or another command. */
	enum jcop4_sm_outer_policy policy = extended && size == 16 && response[0] == 0x99 &&
									    apdu.sw1 == 0x6A && apdu.sw2 == 0x82
							    ? JCOP4_SM_OUTER_PSO_STATUS_6A82
							    : JCOP4_SM_OUTER_9000;
	if (jcop4_sm_open_report_policy_ex(crypto->provider.libctx, &crypto->sm, response, size, plain, capacity,
			    plain_size, &sw, policy, &decoded))
		goto out;
	report->authenticated = 1;
	report->sw = sw;
	result = sw == 0x9000 ? SC_SUCCESS : sw == 0x6982 ? SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
							  : SC_ERROR_CARD_CMD_FAILED;
out:
	sc_mem_clear(header, sizeof(header));
	sc_mem_clear(body, sizeof(body));
	sc_mem_clear(response, sizeof(response));
	if (result) {
		*plain_size = 0;
		iasecc_chipdoc_invalidate_card(card);
	}
	return result;
}

int
iasecc_chipdoc_channel_select_application(struct sc_card *card,
		struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	unsigned char plain[1];
	size_t size;
	const unsigned char select[4] = {0, 0xA4, 4, 0x0C};
	const struct iasecc_chipdoc_profile *profile = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	int rv;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->reset_required = prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required;
	rv = chipdoc_signing_ready(card, IASECC_CHIPDOC_LOGGED_IN, 8, &prv);
	if (rv)
		return rv;
	uint64_t generation = prv->chipdoc_session.generation;
	rv = chipdoc_signature_exchange(card, IASECC_CHIPDOC_LOGGED_IN, 8, select, profile->aid, profile->aid_len,
			0, plain, sizeof(plain), &size, report);
	if (!rv && size)
		rv = SC_ERROR_INVALID_DATA;
	if (!rv)
		rv = iasecc_chipdoc_record(&prv->chipdoc_session, generation, IASECC_CHIPDOC_RESPONSE_APPLICATION, 0x9000, 0, 0);
	sc_mem_clear(plain, sizeof(plain));
	if (rv)
		iasecc_chipdoc_invalidate_card(card);
	return rv;
}

int
iasecc_chipdoc_channel_set_security_env(struct sc_card *card, const struct sc_security_env *env,
		int se_num, struct iasecc_chipdoc_channel_report *report)
{
	struct iasecc_private_data *prv = NULL;
	unsigned char plain[1];
	size_t size;
	const unsigned char mse[4] = {0, 0x22, 0x81, 0xB6}, mse_data[4] = {0x91, 2, 0x28, 0x91};
	const struct iasecc_chipdoc_profile *profile = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	int rv;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->reset_required = prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required;
	if (!env)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (se_num || env->flags != (SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT) ||
			env->operation != SC_SEC_OPERATION_SIGN || env->algorithm != SC_ALGORITHM_RSA || env->key_ref_len != 1 ||
			env->key_ref[0] != profile->signing_reference || env->key_size_bits != profile->signing_bits ||
			env->algorithm_flags != (SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256) ||
			env->file_ref.len || env->file_ref.aid.len || env->target_file_ref.len || env->target_file_ref.aid.len)
		return SC_ERROR_NOT_SUPPORTED;
	for (size_t i = 0; i < SC_SEC_ENV_MAX_PARAMS; i++)
		if (env->params[i].param_type || env->params[i].value || env->params[i].value_len)
			return SC_ERROR_NOT_SUPPORTED;
	int selected = prv && prv->chipdoc_session.phase == IASECC_CHIPDOC_APPLICATION;
	rv = chipdoc_signing_ready(card, selected ? IASECC_CHIPDOC_APPLICATION : IASECC_CHIPDOC_LOGGED_IN,
			selected ? 10 : 8, &prv);
	if (rv)
		return rv;
	uint64_t generation = prv->chipdoc_session.generation;
	if (!selected)
		rv = iasecc_chipdoc_channel_select_application(card, report);
	if (!rv)
		rv = iasecc_chipdoc_signing_key(&prv->chipdoc_session, env->key_ref[0], env->key_size_bits, env->algorithm_flags);
	if (!rv)
		rv = chipdoc_signature_exchange(card, IASECC_CHIPDOC_APPLICATION, 10, mse, mse_data, sizeof(mse_data),
				0, plain, sizeof(plain), &size, report);
	if (!rv && size)
		rv = SC_ERROR_INVALID_DATA;
	if (!rv)
		rv = iasecc_chipdoc_record(&prv->chipdoc_session, generation, IASECC_CHIPDOC_RESPONSE_MSE, 0x9000,
				env->key_ref[0], env->key_size_bits);
	sc_mem_clear(plain, sizeof(plain));
	if (rv)
		iasecc_chipdoc_invalidate_card(card);
	return rv;
}

int
iasecc_chipdoc_channel_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len,
		struct iasecc_chipdoc_signature_report *report)
{
	struct iasecc_private_data *prv = NULL;
	unsigned char signature[256];
	size_t size;
	const unsigned char pso[4] = {0, 0x2A, 0x9E, 0x9A};
	int rv, closed;
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc"))
		return SC_ERROR_NOT_SUPPORTED;
	prv = card->drv_data;
	if (prv)
		report->channel.reset_required = prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required;
	if (!in || in_len != 32 || !out)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (out_len < 256)
		return SC_ERROR_BUFFER_TOO_SMALL;
	rv = chipdoc_signing_ready(card, IASECC_CHIPDOC_MSE, 12, &prv);
	if (rv)
		return rv;
	if (prv->chipdoc_session.key_reference != 0x91 || prv->chipdoc_session.key_bits != 2048)
		return SC_ERROR_NOT_SUPPORTED;
	uint64_t generation = prv->chipdoc_session.generation;
	rv = chipdoc_signature_exchange(card, IASECC_CHIPDOC_MSE, 12, pso, in, in_len,
			1, signature, sizeof(signature), &size, &report->channel);
	if (!rv && size != sizeof(signature))
		rv = SC_ERROR_INVALID_DATA;
	if (!rv)
		rv = iasecc_chipdoc_record(&prv->chipdoc_session, generation, IASECC_CHIPDOC_RESPONSE_SIGNATURE, 0x9000, 0, 0);
	if (rv)
		iasecc_chipdoc_invalidate_card(card);
	closed = iasecc_chipdoc_transaction_close(card, &report->close);
	report->channel.reset_required = report->close.reset_required;
	if (!rv && closed)
		rv = closed;
	if (!rv && !report->close.complete)
		rv = SC_ERROR_NOT_ALLOWED;
	if (!rv)
		memmove(out, signature, sizeof(signature));
	sc_mem_clear(signature, sizeof(signature));
	return rv ? rv : 256;
}

#else

int
iasecc_chipdoc_detect(struct sc_card *card, struct sc_card_driver *driver)
{
	(void)card;
	(void)driver;
	return 0;
}
/* Unsupported crypto builds preserve all legacy drivers. No secret context,
 * APDU, session transition or algorithm advertisement in this branch. */
int
iasecc_chipdoc_channel_supported(struct sc_card *card)
{
	(void)card;
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_pin_status(struct sc_card *card, int *logged_in)
{
	(void)card;
	if (logged_in)
		*logged_in = SC_PIN_STATE_UNKNOWN;
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_select_application(struct sc_card *card,
		struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_set_security_env(struct sc_card *card, const struct sc_security_env *env,
		int se_num, struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	(void)env;
	(void)se_num;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len,
		struct iasecc_chipdoc_signature_report *report)
{
	(void)card;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_verify_pin(struct sc_card *card, const struct sc_pin_cmd_data *data,
		int *tries_left, struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	(void)data;
	if (tries_left)
		*tries_left = -1;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_transaction_begin(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_transaction_report *report)
{
	(void)p15;
	(void)key;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_query_pin(struct sc_card *card, unsigned int reference,
		int *tries_left, struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	(void)reference;
	if (tries_left)
		*tries_left = -1;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_bootstrap(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_bootstrap_report *report)
{
	(void)p15;
	(void)key;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_open(struct sc_card *card, const unsigned char *initial,
		size_t size, struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	(void)initial;
	(void)size;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
int
iasecc_chipdoc_channel_select_mf(struct sc_card *card,
		enum iasecc_chipdoc_mf_encoding encoding, struct iasecc_chipdoc_channel_report *report)
{
	(void)card;
	(void)encoding;
	if (report)
		memset(report, 0, sizeof(*report));
	return SC_ERROR_NOT_SUPPORTED;
}
#endif
