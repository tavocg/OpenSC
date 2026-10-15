/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Explicit per-card routing after native objects are decoded. No automatic
 * discovery/configuration/init, capability or mechanism announcement. Callers
 * serialize APIs and keep card/context/reader and PKCS15 owners alive. */
#ifndef OPENSC_IASECC_CHIPDOC_ROUTING_H
#define OPENSC_IASECC_CHIPDOC_ROUTING_H
#include "iasecc-chipdoc-sm.h"
#include <stdlib.h>

enum iasecc_chipdoc_routed_operation {
	IASECC_CHIPDOC_ROUTE_NONE,
	IASECC_CHIPDOC_ROUTE_PIN,
	IASECC_CHIPDOC_ROUTE_SELECT,
	IASECC_CHIPDOC_ROUTE_MSE,
	IASECC_CHIPDOC_ROUTE_SIGN,
	IASECC_CHIPDOC_ROUTE_LOGOUT,
	IASECC_CHIPDOC_ROUTE_DETACH
};
struct iasecc_chipdoc_routing_report {
	enum iasecc_chipdoc_routed_operation operation;
	int result;
	struct iasecc_chipdoc_channel_report channel;
	struct iasecc_chipdoc_transaction_report startup, close;
};
struct iasecc_chipdoc_routing {
	struct sc_card *card;
	struct sc_context *context;
	struct sc_reader *reader;
	struct sc_card_operations *target;
	struct sc_card_operations original, filtered;
	struct sc_pkcs15_card *p15;
	const struct sc_pkcs15_object *key, *pin;
	void (*original_clear)(struct sc_pkcs15_card *);
	int detached, invalid;
	struct iasecc_chipdoc_routing_report last;
};
static inline struct iasecc_chipdoc_routing *
chipdoc_route(struct sc_card *card)
{
	if (!card || !card->driver || !card->driver->short_name || strcmp(card->driver->short_name, "iasecc") || !card->drv_data)
		return NULL;
	struct iasecc_private_data *prv = card->drv_data;
	struct iasecc_chipdoc_routing *b = prv->chipdoc_routing;
	return b && b->card == card ? b : NULL;
}
static inline void chipdoc_route_clear(struct sc_pkcs15_card *p15);
static inline int
chipdoc_route_close(struct iasecc_chipdoc_routing *b, int result)
{
	int closed = iasecc_chipdoc_transaction_close(b->card, &b->last.close);
	b->last.result = result ? result : closed;
	return b->last.result;
}
static inline int
chipdoc_route_valid(struct iasecc_chipdoc_routing *b)
{
	struct iasecc_chipdoc_pkcs15_operation op;
	unsigned int count = 0;
	int key_seen = 0, pin_seen = 0, rv;
	if (!b || b->detached || b->invalid || b->context != b->card->ctx || b->reader != b->card->reader ||
			b->target != b->card->ops || !b->p15 || b->p15->card != b->card ||
			b->p15->magic != SC_PKCS15_CARD_MAGIC || b->p15->ops.clear != chipdoc_route_clear || b->p15->opts.use_pin_cache)
		return SC_ERROR_NOT_ALLOWED;
	/* Check membership BEFORE dereferencing any borrowed object pointer. */
	for (const struct sc_pkcs15_object *o = b->p15->obj_list; o; o = o->next) {
		if (++count > IASECC_CHIPDOC_OBJECT_LIMIT)
			return SC_ERROR_INVALID_DATA;
		if (o == b->key)
			key_seen++;
		if (o == b->pin)
			pin_seen++;
	}
	if (key_seen != 1 || pin_seen != 1)
		return SC_ERROR_NOT_ALLOWED;
	rv = iasecc_chipdoc_pkcs15_operation(b->p15, b->key, &op);
	if (rv)
		return rv;
	if (op.pin != b->pin)
		return SC_ERROR_NOT_ALLOWED;
	return iasecc_chipdoc_channel_supported(b->card);
}
static inline int
chipdoc_route_require(struct iasecc_chipdoc_routing *b)
{
	int rv = chipdoc_route_valid(b);
	if (rv && b && !b->detached) {
		b->invalid = 1;
		iasecc_chipdoc_invalidate_card(b->card);
		(void)chipdoc_route_close(b, rv);
	}
	return rv;
}
static inline int
chipdoc_route_idle(struct iasecc_chipdoc_routing *b)
{
	int rv = chipdoc_route_require(b);
	if (rv)
		return rv;
	struct iasecc_private_data *prv = b->card->drv_data;
	if (prv->chipdoc_transaction.active || prv->chipdoc_session.channel || prv->chipdoc_recovery_required ||
			prv->chipdoc_session.phase != IASECC_CHIPDOC_INACTIVE)
		return SC_ERROR_NOT_ALLOWED;
	return SC_SUCCESS;
}
static inline int
chipdoc_route_pin(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv, tries = -1;
	if (!data)
		return SC_ERROR_INVALID_ARGUMENTS;
	data->pin1.tries_left = -1;
	data->pin1.max_tries = 0;
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
	rv = chipdoc_route_require(b);
	if (rv)
		return rv;
	if (data->pin_type != SC_AC_CHV || data->pin_reference != 1 || data->puk_reference ||
			data->apdu || data->pin2.data || data->pin2.len)
		return SC_ERROR_NOT_SUPPORTED;
	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		if ((data->flags && data->flags != SC_PIN_CMD_STATUS_ONLY) || data->pin1.data || data->pin1.len)
			return SC_ERROR_INVALID_ARGUMENTS;
		rv = iasecc_chipdoc_channel_pin_status(card, &data->pin1.logged_in);
		if (rv) {
			(void)chipdoc_route_close(b, rv);
			return rv;
		}
		data->pin1.min_length = 6;
		data->pin1.max_length = 14;
		data->pin1.encoding = SC_PIN_ENCODING_ASCII;
		return SC_SUCCESS;
	}
	if (data->cmd != SC_PIN_CMD_VERIFY)
		return SC_ERROR_NOT_SUPPORTED;
	if (data->flags || data->pin1.encoding != SC_PIN_ENCODING_ASCII ||
			(data->pin1.min_length && data->pin1.min_length != 6) || (data->pin1.max_length && data->pin1.max_length != 14))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!data->pin1.data || data->pin1.len < 6 || data->pin1.len > 14)
		return SC_ERROR_INVALID_PIN_LENGTH;
	rv = chipdoc_route_idle(b);
	if (rv)
		return rv;
	for (size_t i = 0; i < data->pin1.len; i++)
		if (data->pin1.data[i] < 0x20 || data->pin1.data[i] > 0x7E)
			return SC_ERROR_INVALID_ARGUMENTS;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_PIN;
	rv = iasecc_chipdoc_transaction_begin(b->p15, b->key, &b->last.startup);
	if (!rv)
		rv = iasecc_chipdoc_channel_query_pin(card, 1, &tries, &b->last.channel);
	if (!rv)
		rv = iasecc_chipdoc_channel_verify_pin(card, data, &tries, &b->last.channel);
	data->pin1.tries_left = tries;
	if (rv)
		return chipdoc_route_close(b, rv);
	data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
	b->last.result = SC_SUCCESS;
	return SC_SUCCESS;
}
static inline int
chipdoc_route_select(struct sc_card *card, const struct sc_path *path, struct sc_file **file)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_require(b);
	if (file)
		*file = NULL;
	if (rv)
		return rv;
	if (!path)
		return SC_ERROR_INVALID_ARGUMENTS;
	struct iasecc_private_data *prv = card->drv_data;
	if (!prv->chipdoc_transaction.active) {
		rv = chipdoc_route_idle(b);
		if (rv)
			return rv;
		return b->original.select_file ? b->original.select_file(card, path, file) : SC_ERROR_NOT_SUPPORTED;
	}
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	if (file || path->type != SC_PATH_TYPE_PATH || path->len || path->aid.len != p->aid_len ||
			memcmp(path->aid.value, p->aid, p->aid_len))
		return SC_ERROR_NOT_ALLOWED;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_SELECT;
	rv = iasecc_chipdoc_channel_select_application(card, &b->last.channel);
	b->last.result = rv;
	return rv ? chipdoc_route_close(b, rv) : SC_SUCCESS;
}
static inline int
chipdoc_route_mse(struct sc_card *card, const struct sc_security_env *env, int number)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_require(b);
	if (rv)
		return rv;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_MSE;
	int logged_in;
	rv = iasecc_chipdoc_channel_pin_status(card, &logged_in);
	if (rv || logged_in != SC_PIN_STATE_LOGGED_IN)
		return chipdoc_route_close(b, rv ? rv : SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	rv = iasecc_chipdoc_channel_set_security_env(card, env, number, &b->last.channel);
	b->last.result = rv;
	return rv ? chipdoc_route_close(b, rv) : SC_SUCCESS;
}
static inline int
chipdoc_route_sign(struct sc_card *card, const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_require(b);
	if (rv)
		return rv;
	struct iasecc_chipdoc_signature_report report;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_SIGN;
	int logged_in;
	rv = iasecc_chipdoc_channel_pin_status(card, &logged_in);
	if (rv || logged_in != SC_PIN_STATE_LOGGED_IN)
		return chipdoc_route_close(b, rv ? rv : SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	rv = iasecc_chipdoc_channel_compute_signature(card, in, in_len, out, out_len, &report);
	b->last.channel = report.channel;
	b->last.close = report.close;
	b->last.result = rv;
	if (rv < 0 && ((struct iasecc_private_data *)card->drv_data)->chipdoc_transaction.active)
		return chipdoc_route_close(b, rv);
	return rv;
}
static inline int
chipdoc_route_read(struct sc_card *card, unsigned int offset, unsigned char *out, size_t size, unsigned long *flags)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_idle(b);
	if (rv)
		return rv;
	return b->original.read_binary ? b->original.read_binary(card, offset, out, size, flags) : SC_ERROR_NOT_SUPPORTED;
}
static inline int
chipdoc_route_record(struct sc_card *card, unsigned int record, unsigned int offset,
		unsigned char *out, size_t size, unsigned long flags)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_idle(b);
	if (rv)
		return rv;
	return b->original.read_record ? b->original.read_record(card, record, offset, out, size, flags) : SC_ERROR_NOT_SUPPORTED;
}
static inline int
chipdoc_route_data(struct sc_card *card, unsigned int tag, unsigned char *out, size_t size)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	int rv = chipdoc_route_idle(b);
	if (rv)
		return rv;
	return b->original.get_data ? b->original.get_data(card, tag, out, size) : SC_ERROR_NOT_SUPPORTED;
}
static inline int
chipdoc_route_logout(struct sc_card *card)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	if (!b)
		return SC_ERROR_NOT_ALLOWED;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_LOGOUT;
	return chipdoc_route_close(b, SC_SUCCESS);
}
/* Detach references BEFORE owner frees native objects. Keep the restricted
 * table/card-owned tombstone until finish; never fall back to plain IAS. */
static inline int
iasecc_chipdoc_routing_remove(struct sc_card *card, struct sc_pkcs15_card *p15,
		struct iasecc_chipdoc_routing_report *report)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	if (report)
		memset(report, 0, sizeof(*report));
	if (!b)
		return SC_ERROR_NOT_ALLOWED;
	if (b->detached) {
		int rv = iasecc_chipdoc_transaction_close(card, &b->last.close);
		b->last.result = rv;
		if (report)
			*report = b->last;
		return rv;
	}
	if (p15 != b->p15)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(&b->last, 0, sizeof(b->last));
	b->last.operation = IASECC_CHIPDOC_ROUTE_DETACH;
	int rv = chipdoc_route_close(b, SC_SUCCESS);
	if (p15->ops.clear == chipdoc_route_clear)
		p15->ops.clear = b->original_clear;
	/* Keep caching disabled; a failed detach must not enable revalidation. */
	p15->opts.use_pin_cache = 0;
	b->p15 = NULL;
	b->key = b->pin = NULL;
	b->detached = 1;
	if (report)
		*report = b->last;
	return rv;
}
static inline void
chipdoc_route_clear(struct sc_pkcs15_card *p15)
{
	struct iasecc_chipdoc_routing *b = p15 ? chipdoc_route(p15->card) : NULL;
	if (!b || b->p15 != p15)
		return;
	void (*clear)(struct sc_pkcs15_card *) = b->original_clear;
	(void)iasecc_chipdoc_routing_remove(p15->card, p15, NULL);
	if (clear)
		clear(p15);
}
static inline int
chipdoc_route_finish(struct sc_card *card)
{
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	if (!b)
		return SC_ERROR_NOT_ALLOWED;
	int rv = iasecc_chipdoc_routing_remove(card, b->p15, NULL);
	int (*finish)(struct sc_card *) = b->original.finish;
	/* Restore solely for destruction, never while card remains available. */
	if (b->target == card->ops)
		*card->ops = b->original;
	else
		rv = rv ? rv : SC_ERROR_CARD_RESET;
	((struct iasecc_private_data *)card->drv_data)->chipdoc_routing = NULL;
	sc_mem_clear(b, sizeof(*b));
	free(b);
	int finished = finish ? finish(card) : SC_ERROR_NOT_SUPPORTED;
	return rv ? rv : finished;
}
static inline int
iasecc_chipdoc_routing_install(struct sc_pkcs15_card *p15, const struct sc_pkcs15_object *key)
{
#if defined(IASECC_CHIPDOC_NO_CRYPTO)
	(void)p15;
	(void)key;
	return SC_ERROR_NOT_SUPPORTED;
#else
	struct iasecc_chipdoc_pkcs15_operation op;
	struct sc_card *card = p15 ? p15->card : NULL;
	int rv = iasecc_chipdoc_channel_supported(card);
	if (rv)
		return rv;
	struct iasecc_private_data *prv = card->drv_data;
	if (prv->chipdoc_routing || prv->chipdoc_transaction.active || prv->chipdoc_session.channel ||
			prv->chipdoc_session.phase != IASECC_CHIPDOC_INACTIVE || prv->chipdoc_recovery_required)
		return SC_ERROR_NOT_ALLOWED;
	if (!card->ops || card->ops == card->driver->ops || !card->ops->finish || !card->ops->card_reader_lock_obtained ||
			p15->magic != SC_PKCS15_CARD_MAGIC || !card->reader->ops || !card->reader->ops->lock ||
			!card->reader->ops->unlock || !card->reader->ops->reset)
		return SC_ERROR_NOT_SUPPORTED;
	rv = iasecc_chipdoc_pkcs15_operation(p15, key, &op);
	if (rv)
		return rv;
	/* The future opt-in initializer must supply the justified narrow table.
	 * Do not inherit the ordinary IAS RNG/generation/raw/other-hash defaults
	 * or rewrite limits/capabilities here to make this routing pass. */
	if ((card->caps & ~(SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_USE_FCI_AC | SC_CARD_CAP_ISO7816_PIN_INFO)) ||
			card->algorithm_count != 1 || !card->algorithms || card->algorithms[0].algorithm != SC_ALGORITHM_RSA ||
			card->algorithms[0].key_length != 2048 || card->algorithms[0].flags != op.algorithm_flags)
		return SC_ERROR_NOT_SUPPORTED;
	struct iasecc_chipdoc_routing *b = calloc(1, sizeof(*b));
	if (!b)
		return SC_ERROR_OUT_OF_MEMORY;
	b->card = card;
	b->context = card->ctx;
	b->reader = card->reader;
	b->target = card->ops;
	b->original = *card->ops;
	b->p15 = p15;
	b->key = key;
	b->pin = op.pin;
	b->original_clear = p15->ops.clear;
	/* Only readonly idle metadata, local pure decoding, measured operations
	 * and lifecycle survive. No RNG/admin/writes/plain VERIFY/GET RESPONSE. */
	b->filtered.read_binary = chipdoc_route_read;
	b->filtered.read_record = chipdoc_route_record;
	b->filtered.get_data = chipdoc_route_data;
	b->filtered.select_file = chipdoc_route_select;
	b->filtered.pin_cmd = chipdoc_route_pin;
	b->filtered.set_security_env = chipdoc_route_mse;
	b->filtered.compute_signature = chipdoc_route_sign;
	b->filtered.logout = chipdoc_route_logout;
	b->filtered.finish = chipdoc_route_finish;
	b->filtered.card_reader_lock_obtained = b->original.card_reader_lock_obtained;
	b->filtered.check_sw = b->original.check_sw;
	b->filtered.process_fci = b->original.process_fci;
	b->filtered.construct_fci = b->original.construct_fci;
	prv->chipdoc_routing = b;
	p15->opts.use_pin_cache = 0;
	p15->ops.clear = chipdoc_route_clear;
	*card->ops = b->filtered;
	return SC_SUCCESS;
#endif
}
static inline int
iasecc_chipdoc_routing_last_report(struct sc_card *card, struct iasecc_chipdoc_routing_report *report)
{
	if (!report)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(report, 0, sizeof(*report));
	struct iasecc_chipdoc_routing *b = chipdoc_route(card);
	if (!b)
		return SC_ERROR_NOT_ALLOWED;
	*report = b->last;
	return SC_SUCCESS;
}
#endif
