/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Select the measured profile from already decoded public PKCS#15 objects.
 * No discovery, certificate/credential bytes, card I/O or authentication.
 * Operation policy checks cache presence without reading its contents.
 */
#ifndef OPENSC_IASECC_CHIPDOC_PKCS15_H
#define OPENSC_IASECC_CHIPDOC_PKCS15_H
#include "iasecc-chipdoc.h"
#include "pkcs15.h"

struct iasecc_chipdoc_key_metadata {
	unsigned int reference, bits, pin_reference;
	struct iasecc_chipdoc_pin_policy pin;
};
/* Borrowed object view valid only while the caller keeps PKCS15 objects alive.
 * No channel, credentials, login/counter cache or driver binding is installed. */
struct iasecc_chipdoc_pkcs15_operation {
	const struct sc_pkcs15_object *pin;
	unsigned long algorithm_flags;
	int selects_application;
};
#define IASECC_CHIPDOC_OBJECT_LIMIT 512

static inline int
iasecc_chipdoc_pkcs15_key(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct sc_aid *aid,
		struct iasecc_chipdoc_key_metadata *metadata)
{
	const struct iasecc_chipdoc_profile *profile = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	const struct sc_pkcs15_prkey_info *info;
	const struct sc_pkcs15_auth_info *pin = NULL;
	const struct sc_pkcs15_object *object;
	unsigned int count = 0, key_seen = 0, pins = 0, apps = 0;
	if (aid)
		memset(aid, 0, sizeof(*aid));
	if (metadata)
		memset(metadata, 0, sizeof(*metadata));
	if (!aid || !metadata || !p15 || !p15->card || !p15->app || !key ||
			(p15->flags & SC_PKCS15_CARD_FLAG_EMULATED) || key->type != SC_PKCS15_TYPE_PRKEY_RSA ||
			!key->data || key->session_object || key->emulated || !key->auth_id.len ||
			key->auth_id.len > sizeof(key->auth_id.value) ||
			iasecc_chipdoc_candidate(&p15->card->atr, &p15->app->aid) != profile->id ||
			p15->card->app_count < 1 || p15->card->app_count > SC_MAX_CARD_APPS)
		return SC_ERROR_NOT_SUPPORTED;
	info = key->data;
	if (info->native != 1 || info->key_reference != (int)profile->signing_reference ||
			info->modulus_length != profile->signing_bits ||
			!(info->usage & (SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)))
		return SC_ERROR_NOT_SUPPORTED;
	/* Reject a key/PKCS#15 DDO explicitly scoped to another application. */
	if ((info->path.aid.len && iasecc_chipdoc_candidate(&p15->card->atr, &info->path.aid) != profile->id) ||
			(p15->app->ddo.aid.len && iasecc_chipdoc_candidate(&p15->card->atr, &p15->app->ddo.aid) != profile->id))
		return SC_ERROR_NOT_SUPPORTED;
	for (int i = 0; i < p15->card->app_count; i++) {
		const struct sc_app_info *app = p15->card->app[i];
		if (app && iasecc_chipdoc_candidate(&p15->card->atr, &app->aid) == profile->id)
			apps++;
	}
	if (apps != 1)
		return SC_ERROR_NOT_SUPPORTED;
	for (object = p15->obj_list; object; object = object->next) {
		if (++count > IASECC_CHIPDOC_OBJECT_LIMIT)
			return SC_ERROR_INVALID_DATA;
		if (object == key)
			key_seen++;
		if (object->type == SC_PKCS15_TYPE_AUTH_PIN && object->data) {
			const struct sc_pkcs15_auth_info *candidate = object->data;
			if (candidate->auth_id.len == key->auth_id.len &&
					!memcmp(candidate->auth_id.value, key->auth_id.value, key->auth_id.len)) {
				if (object->session_object || object->emulated || ++pins != 1)
					return SC_ERROR_NOT_SUPPORTED;
				pin = candidate;
			}
		}
	}
	if (key_seen != 1 || !pin || pin->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN ||
			pin->attrs.pin.reference != (int)profile->pin_reference ||
			(pin->attrs.pin.flags & (SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_SO_PIN | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)))
		return SC_ERROR_NOT_SUPPORTED;
	/* Copy decoded public formatting only. Do not infer logged-in state,
	 * attempts, credential contents or D004 parameters from these objects. */
	*aid = p15->app->aid;
	*metadata = (struct iasecc_chipdoc_key_metadata){
			.reference = (unsigned)info->key_reference, .bits = (unsigned)info->modulus_length, .pin_reference = (unsigned)pin->attrs.pin.reference, .pin = {pin->attrs.pin.min_length, pin->attrs.pin.max_length, pin->attrs.pin.type, pin->attrs.pin.flags}
	 };
	return SC_SUCCESS;
}

/* The operation contract is stricter than discovery/bootstrap metadata.
 * Empty native SDO path; optional known AID is selected by use_key. Global
 * CHV has no path/AID, so the framework cannot reselect before VERIFY. */
static inline int
iasecc_chipdoc_pkcs15_operation(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_pkcs15_operation *operation)
{
	struct sc_aid aid;
	struct iasecc_chipdoc_key_metadata metadata;
	const struct sc_pkcs15_prkey_info *info;
	const struct sc_pkcs15_object *pin = NULL;
	unsigned int count = 0;
	if (!operation)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(operation, 0, sizeof(*operation));
	int rv = iasecc_chipdoc_pkcs15_key(p15, key, &aid, &metadata);
	if (rv)
		return rv;
	info = key->data;
	if (info->path.len || (info->path.aid.len && info->path.type != SC_PATH_TYPE_PATH) ||
			metadata.pin.minimum != 6 || metadata.pin.maximum != 14 || metadata.pin.format != SC_PKCS15_PIN_TYPE_UTF8 ||
			metadata.pin.flags != (SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED))
		return SC_ERROR_NOT_SUPPORTED;
	for (const struct sc_pkcs15_object *object = p15->obj_list; object; object = object->next) {
		if (++count > IASECC_CHIPDOC_OBJECT_LIMIT)
			return SC_ERROR_INVALID_DATA;
		if (object->type != SC_PKCS15_TYPE_AUTH_PIN || !object->data)
			continue;
		/* Inspect only presence, never credential bytes. Do not silently discard
		 * an existing cache or permit generic revalidation of another PIN. */
		if (object->content.value || object->content.len)
			return SC_ERROR_NOT_ALLOWED;
		const struct sc_pkcs15_auth_info *auth = object->data;
		if (auth->auth_id.len == key->auth_id.len && !memcmp(auth->auth_id.value, key->auth_id.value, key->auth_id.len)) {
			if (auth->auth_method != SC_AC_CHV || auth->path.len || auth->path.aid.len)
				return SC_ERROR_NOT_SUPPORTED;
			pin = object;
		}
	}
	if (!pin)
		return SC_ERROR_NOT_SUPPORTED;
	operation->pin = pin;
	operation->algorithm_flags = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256;
	operation->selects_application = info->path.aid.len != 0;
	return SC_SUCCESS;
}

/* Explicit private opt-in, no I/O/algorithm announcement/driver binding.
 * All validation precedes mutation. A caller enabling this operation must
 * keep caching disabled through authentication/signing; no saved PIN is read
 * or cleared, and failed validation leaves every option/object unchanged. */
static inline int
iasecc_chipdoc_pkcs15_disable_pin_cache(struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_pkcs15_operation *operation)
{
	int rv = iasecc_chipdoc_pkcs15_operation(p15, key, operation);
	if (!rv)
		p15->opts.use_pin_cache = 0;
	return rv;
}
#endif
