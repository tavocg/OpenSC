/*
 * PKCS15 emulation layer for IAS/ECC card.
 *
 * Copyright (C) 2016, Viktor Tarasov <viktor.tarasov@gmail.com>
 * Copyright (C) 2004, Bud P. Bruegger <bud@comune.grosseto.it>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef ENABLE_OPENSSL
#include <openssl/x509v3.h>
#endif

#include "internal.h"
#include "pkcs15.h"
#include "../pkcs15init/pkcs15-iasecc.h"
#include "iasecc.h"
#include "aux-data.h"

#define IASECC_GEMALTO_MD_APPLICATION_NAME "CSP"
#define IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL "Default Key Container"

static int
_iasecc_md_update_keyinfo(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *dobj, int default_cont)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	struct sc_pkcs15_data *ddata = NULL;
	struct sc_pkcs15_id id;
	int rv, offs;
	unsigned flags;
	int private_obj;

	LOG_FUNC_CALLED(ctx);

	if (!dobj)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	private_obj = dobj->flags & SC_PKCS15_CO_FLAG_PRIVATE;
	rv = sc_pkcs15_read_data_object(p15card, (struct sc_pkcs15_data_info *)dobj->data, private_obj, &ddata);
	LOG_TEST_RET(ctx, rv, "Failed to read container DATA object data");

	/* [0] = 0x01
	 * [1] = length
	 * [2 .. 2 + length] = ID
	 * [2 + length] = 0x02
	 * [2 + length + 1] = 0x01
	 * [3 + length + 2] = flags
	 */
	offs = 0;
	if (ddata->data_len < 2 || *(ddata->data + offs++) != 0x01)   {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	id.len = *(ddata->data + offs++);
	if (id.len > sizeof(id.value) || ddata->data_len < offs + id.len + 3) {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}
	memcpy(id.value, ddata->data + offs, id.len);
	offs += (int)id.len;

	if (*(ddata->data + offs++) != 0x02)  {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}
	if (*(ddata->data + offs++) != 0x01)  {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	flags = *(ddata->data + offs);
	if (default_cont)
		flags |= SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER;

	sc_pkcs15_free_data_object(ddata);

	rv = sc_pkcs15_find_prkey_by_id(p15card, &id, &prkey_object);
	LOG_TEST_RET(ctx, rv, "Find related PrKey error");

	prkey_info = (struct sc_pkcs15_prkey_info *)prkey_object->data;
	if (prkey_info->aux_data == NULL)   {
		rv = sc_aux_data_allocate(ctx, &prkey_info->aux_data, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot allocate MD auxiliary data");
	}

	rv = sc_aux_data_set_md_guid(ctx, prkey_info->aux_data, dobj->label);
	LOG_TEST_RET(ctx, rv, "Cannot set MD CMAP Guid");

	rv = sc_aux_data_set_md_flags(ctx, prkey_info->aux_data, flags);
	LOG_TEST_RET(ctx, rv, "Cannot set MD CMAP record flags");

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * CPx cards have an undocumented issue: they lack of
 * Algorithm's reference into their PKCS's ASN1 encoding.
 */
static int
_iasecc_cpx_fixup_prkdf(struct sc_pkcs15_card *p15card)
{
	struct sc_context * const ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pkobjs[32];
	int ii, count;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, pkobjs, sizeof(pkobjs)/sizeof(pkobjs[0]));
	LOG_TEST_RET(ctx, rv, "Cannot get PRKEY objects list");

	count = rv;
	for(ii=0; ii<count; ii++)   {
		rv = iasecc_pkcs15_encode_supported_algos(p15card, pkobjs[ii]);
		LOG_TEST_RET(ctx, rv, "Cannot fix suported_algos");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
_iasecc_is_chipdoc(struct sc_pkcs15_card *p15card)
{
	return p15card->app && iasecc_chipdoc_jcop3(p15card->card, &p15card->app->aid);
}

/* ChipDoc's AODF describes global CHV 1 with path 0001, but that EF is
 * absent. The observed CHV 1 is accessible in MF.
 * Keep the correction separate from ordinary file selection, and restrict it
 * to the IAS/ECC Amos / Generic PKI profile and the affected PIN metadata.
 */
static void
_iasecc_fixup_global_pin_paths(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_object *obj;

	if (!_iasecc_is_chipdoc(p15card))
		return;

	for (obj = p15card->obj_list; obj; obj = obj->next) {
		struct sc_pkcs15_auth_info *info;

		if (obj->type != SC_PKCS15_TYPE_AUTH_PIN || !obj->data)
			continue;
		info = obj->data;
		if (info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN ||
				info->attrs.pin.reference != 1 ||
				(info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_LOCAL) ||
				(info->path.type != SC_PATH_TYPE_PATH && info->path.type != SC_PATH_TYPE_FILE_ID) ||
				info->path.len != 2 || info->path.value[0] != 0 || info->path.value[1] != 1)
			continue;
		if (info->path.aid.len && (info->path.aid.len != p15card->app->aid.len ||
				memcmp(info->path.aid.value, p15card->app->aid.value, info->path.aid.len)))
			continue;

		sc_format_path("3F00", &info->path);
		info->path.type = SC_PATH_TYPE_FILE_ID;
		sc_log(p15card->card->ctx, "ChipDoc: use MF for global CHV 1 instead of path 0001");
	}
}

/* The observed signing key is a native RSA SDO in ChipDoc, not an EF 0003.
 * Keep the AID and key reference, selecting the application before MSE.
 * Other keys and profiles retain their original PKCS#15 paths.
 */
static void
_iasecc_fixup_signing_key_paths(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_object *obj;

	if (!_iasecc_is_chipdoc(p15card))
		return;
	for (obj = p15card->obj_list; obj; obj = obj->next) {
		struct sc_pkcs15_prkey_info *info;

		if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA || !obj->data)
			continue;
		info = obj->data;
		if (!info->native || info->key_reference != 3 || info->modulus_length != 2048 ||
				(info->path.type != SC_PATH_TYPE_PATH && info->path.type != SC_PATH_TYPE_FILE_ID) ||
				info->path.len != 2 || info->path.value[0] != 0 || info->path.value[1] != 3 ||
				info->path.aid.len != p15card->app->aid.len ||
				memcmp(info->path.aid.value, p15card->app->aid.value, info->path.aid.len))
			continue;

		info->path.len = 0;
		memset(info->path.value, 0, sizeof(info->path.value));
		info->path.type = SC_PATH_TYPE_PATH;
		sc_log(p15card->card->ctx, "ChipDoc: select the application for signing SDO 3 instead of EF 0003");
	}
}

/* ChipDoc does not declare a combined hashing algorithm for its signing key.
 * PKCS#11 therefore hashes in software. Do not send that digest through
 * IAS/ECC QSign, which expects the message and has no OpenSSL 3 implementation.
 * Let PKCS#15 prepend DigestInfo and use the verified RSA-PKCS AT operation.
 * Keep declared algorithms, other profiles and other RSA sizes unchanged.
 */
static void
_iasecc_fixup_signature_algorithms(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_object *obj;
	struct sc_card *card = p15card->card;

	if (!_iasecc_is_chipdoc(p15card) || !p15card->tokeninfo ||
			p15card->tokeninfo->supported_algos[0].reference)
		return;
	for (obj = p15card->obj_list; obj; obj = obj->next) {
		struct sc_pkcs15_prkey_info *info;

		if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA || !obj->data)
			continue;
		info = obj->data;
		if (!info->native || info->key_reference != 3 || info->modulus_length != 2048 ||
				!(info->usage & SC_PKCS15_PRKEY_USAGE_SIGN) || info->algo_refs[0] ||
				info->path.type != SC_PATH_TYPE_PATH || info->path.len ||
				info->path.aid.len != p15card->app->aid.len ||
				memcmp(info->path.aid.value, p15card->app->aid.value, info->path.aid.len))
			continue;

		for (int i = 0; i < card->algorithm_count; i++) {
			struct sc_algorithm_info *algo = &card->algorithms[i];
			unsigned long required = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 |
					SC_ALGORITHM_RSA_HASH_NONE;

			if (algo->algorithm == SC_ALGORITHM_RSA && algo->key_length == 2048 &&
					(algo->flags & required) == required &&
					!(algo->flags & SC_ALGORITHM_RSA_RAW))
				algo->flags &= ~SC_ALGORITHM_RSA_HASH_SHA256;
		}
	}
}

/*
 * It is the entry point for models of cards that need some hot patching
 * - Gemalto cards
 * - CPx: fixup algo_refs from the prkey
 */
static int
_iasecc_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *dobjs[32];
	struct sc_pkcs15_data *default_guid = NULL;
	int rv, ii, count;

	LOG_FUNC_CALLED(ctx);

	if (!df)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_parse_df(p15card, df);
	LOG_TEST_RET(ctx, rv, "DF parse error");

	if (df->type == SC_PKCS15_AODF)
		_iasecc_fixup_global_pin_paths(p15card);
	if (df->type == SC_PKCS15_PRKDF) {
		_iasecc_fixup_signing_key_paths(p15card);
		_iasecc_fixup_signature_algorithms(p15card);
	}

	switch(p15card->card->type) {
		/* enumerate the IASECC cards that need a fixup of the keyInfo */
		case SC_CARD_TYPE_IASECC_GEMALTO:
		case SC_CARD_TYPE_IASECC_CPX:
		case SC_CARD_TYPE_IASECC_CPXCL:
			sc_log(ctx, "Warning: the %d card has an invalid DF, hot patch to be applied",
				p15card->card->type);
			break;
		default:
			sc_log(ctx, "the %d card has a proper DF, no need for a hot patch",
				p15card->card->type);
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
			break;
	}

	if (df->type != SC_PKCS15_PRKDF)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sc_log(ctx, "parse of SC_PKCS15_PRKDF");

	rv = _iasecc_cpx_fixup_prkdf(p15card);
	LOG_TEST_RET(ctx, rv, "Cannot fixup PrKDF");

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, dobjs, sizeof(dobjs)/sizeof(dobjs[0]));
	LOG_TEST_RET(ctx, rv, "Cannot get DATA objects list");

	count = rv;
	for(ii=0; ii<count; ii++)   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;
		int private_obj = dobjs[ii]->flags & SC_PKCS15_CO_FLAG_PRIVATE;

		if (strcmp(dinfo->app_label, IASECC_GEMALTO_MD_APPLICATION_NAME))
			continue;

		if (!strcmp(dobjs[ii]->label, IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL))   {
			rv = sc_pkcs15_read_data_object(p15card, (struct sc_pkcs15_data_info *)dobjs[ii]->data, private_obj, &default_guid);
			LOG_TEST_RET(ctx, rv, "Failed to read 'default container' DATA object data");
			break;
		}
	}

	for(ii=0; ii<count; ii++)   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;
		int default_cont = 0;

		if (strcmp(dinfo->app_label, IASECC_GEMALTO_MD_APPLICATION_NAME))
			continue;

		if (!strcmp(dobjs[ii]->label, IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL))
			continue;

		if (default_guid)
			if (strlen(dobjs[ii]->label) == default_guid->data_len)
				if (!memcmp(dobjs[ii]->label, default_guid->data, default_guid->data_len))
					default_cont = 1;

		rv = _iasecc_md_update_keyinfo(p15card, dobjs[ii], default_cont);
		LOG_TEST_RET(ctx, rv, "Cannot update key MD info");
	}

	sc_pkcs15_free_data_object(default_guid);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15emu_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type < SC_CARD_TYPE_IASECC_BASE)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type > SC_CARD_TYPE_IASECC_BASE + 10)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}


static int
sc_pkcs15emu_iasecc_init (struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_bind_internal(p15card, aid);
	LOG_TEST_RET(ctx, rv, "Cannot bind native IAS/ECC application");

	p15card->ops.parse_df = _iasecc_parse_df;
	_iasecc_fixup_global_pin_paths(p15card);
	_iasecc_fixup_signing_key_paths(p15card);
	_iasecc_fixup_signature_algorithms(p15card);

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_pkcs15emu_iasecc_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	if (iasecc_pkcs15emu_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_iasecc_init(p15card, aid);
}
