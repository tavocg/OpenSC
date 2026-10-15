/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Initialization of the measured profile. Limits are ceilings for the measured
 * operation, not advertised physical maxima or discovery/authentication. */
#ifndef OPENSC_IASECC_CHIPDOC_INIT_H
#define OPENSC_IASECC_CHIPDOC_INIT_H
#include "cards.h"
#include "iasecc-chipdoc-sm.h"
#include "scconf/scconf.h"
#include <stdlib.h>

static inline const char *
iasecc_chipdoc_profile_option(const struct sc_card *card)
{
	const char *value = NULL;
	if (!card || !card->ctx || !card->ctx->conf)
		return NULL;
	for (int i = 0; card->ctx->conf_blocks[i]; i++) {
		scconf_block **blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "iasecc");
		if (!blocks)
			continue;
		for (int j = 0; blocks[j]; j++)
			value = scconf_get_str(blocks[j], "chipdoc_profile", value);
		free(blocks);
	}
	return value;
}

static inline int
iasecc_chipdoc_match(struct sc_card *card, struct sc_card_driver *driver)
{
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	const char *value;
	if (!card || card->atr.len != p->atr_len || memcmp(card->atr.value, p->atr, p->atr_len))
		return 0;
	value = iasecc_chipdoc_profile_option(card);
	/* Preserve the existing explicit profile. Other explicit values disable
	 * automatic probing, so a configuration can retain the old dispatch. */
	if (value && !strcmp(value, "cr-rsa2048"))
		return 1;
	if (value && strcmp(value, "auto"))
		return 0;
	return iasecc_chipdoc_detect(card, driver);
}
static inline int
chipdoc_unbound_pin(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	(void)card;
	(void)data;
	return SC_ERROR_NOT_ALLOWED;
}
static inline int
chipdoc_unbound_logout(struct sc_card *card)
{
	(void)card;
	return SC_SUCCESS;
}
static inline int
chipdoc_metadata_read(struct sc_card *card, unsigned int offset, unsigned char *out,
		size_t size, unsigned long *flags)
{
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	/* The protected PSO ceiling does not enable extended public READ. The
	 * ordinary core read loop advances by the actual bytes returned. */
	return iso->read_binary(card, offset, out, size > 256 ? 256 : size, flags);
}
static inline int
chipdoc_metadata_record(struct sc_card *card, unsigned int record, unsigned int offset,
		unsigned char *out, size_t size, unsigned long flags)
{
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	return iso->read_record ? iso->read_record(card, record, offset, out, size > 256 ? 256 : size, flags) : SC_ERROR_NOT_SUPPORTED;
}
static inline int
chipdoc_metadata_data(struct sc_card *card, unsigned int tag, unsigned char *out, size_t size)
{
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	return iso->get_data ? iso->get_data(card, tag, out, size > 256 ? 256 : size) : SC_ERROR_NOT_SUPPORTED;
}
static inline int
iasecc_chipdoc_initialize(struct sc_card *card, const struct sc_card_operations *metadata,
		int (*finish)(struct sc_card *), int (*lock_hook)(struct sc_card *, int))
{
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	struct iasecc_private_data candidate_data = {0};
	struct sc_card candidate;
	if (!card || card->type != SC_CARD_TYPE_IASECC_CHIPDOC ||
			card->atr.len != p->atr_len || memcmp(card->atr.value, p->atr, p->atr_len) ||
			!card->ops || !card->driver || card->ops == card->driver->ops ||
			card->drv_data || card->algorithm_count || card->algorithms || !metadata || !metadata->select_file ||
			!metadata->read_binary || !finish || !lock_hook)
		return SC_ERROR_NOT_SUPPORTED;
	/* Do not raise an explicitly declared smaller card ceiling. A fresh
	 * OpenSC card normally has zero (unset) limits at entry to init. */
	if ((card->max_send_size && card->max_send_size < p->min_send) ||
			(card->max_recv_size && card->max_recv_size < p->min_receive))
		return SC_ERROR_NOT_SUPPORTED;
	candidate = *card;
	candidate.drv_data = &candidate_data;
	candidate.caps = SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_ISO7816_PIN_INFO;
	candidate.max_send_size = p->min_send;
	candidate.max_recv_size = p->min_receive;
	int rv = iasecc_chipdoc_channel_supported(&candidate);
	if (rv)
		return rv;
	struct iasecc_private_data *prv = calloc(1, sizeof(*prv));
	if (!prv)
		return SC_ERROR_OUT_OF_MEMORY;
	rv = _sc_card_add_rsa_alg(card, p->signing_bits,
			SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256, 0);
	if (rv) {
		free(prv);
		return rv;
	}
	struct sc_card_operations ops = {0};
	ops.select_file = metadata->select_file;
	ops.read_binary = chipdoc_metadata_read;
	ops.read_record = chipdoc_metadata_record;
	ops.get_data = chipdoc_metadata_data;
	ops.check_sw = metadata->check_sw;
	ops.process_fci = metadata->process_fci;
	ops.construct_fci = metadata->construct_fci;
	ops.finish = finish;
	ops.card_reader_lock_obtained = lock_hook;
	ops.pin_cmd = chipdoc_unbound_pin;
	ops.logout = chipdoc_unbound_logout;
	prv->chipdoc_enabled = 1;
	card->drv_data = prv;
	card->caps = candidate.caps;
	card->max_send_size = p->min_send;
	card->max_recv_size = p->min_receive;
	card->cla = 0;
	card->type = SC_CARD_TYPE_IASECC_CHIPDOC;
	*card->ops = ops;
	return SC_SUCCESS;
}
#endif
