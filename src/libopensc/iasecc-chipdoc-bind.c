/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native post-bind activation of the explicit measured profile. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iasecc-chipdoc-routing.h"
#include "iasecc.h"
#include "internal.h"
#include "pkcs15.h"

/* Public metadata validation shared by discovery and post-bind activation.
 * Discovery never installs routing or retains the temporary objects. */
int
iasecc_chipdoc_pkcs15_validate(struct sc_pkcs15_card *p15, struct sc_pkcs15_object **key_out)
{
	struct sc_pkcs15_object *objects[32], *key = NULL;
	struct iasecc_chipdoc_pkcs15_operation operation;
	int rv;
	if (!key_out)
		return SC_ERROR_INVALID_ARGUMENTS;
	*key_out = NULL;
	if (!p15 || !iasecc_chipdoc_configured(p15->card))
		return SC_ERROR_NOT_SUPPORTED;
	if (p15->flags & SC_PKCS15_CARD_FLAG_EMULATED)
		return SC_ERROR_NOT_SUPPORTED;
	int count = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_PRKEY_RSA, objects, 32);
	if (count < 0)
		return count;
	if (!count || count >= 32)
		return SC_ERROR_NOT_SUPPORTED;
	for (int i = 0; i < count; i++) {
		const struct sc_pkcs15_prkey_info *info = objects[i]->data;
		if (!info || info->key_reference != 0x91)
			continue;
		if (key)
			return SC_ERROR_NOT_SUPPORTED;
		key = objects[i];
	}
	if (!key)
		return SC_ERROR_NOT_SUPPORTED;
	count = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_AUTH_PIN, objects, 32);
	if (count < 0)
		return count;
	if (!count || count >= 32)
		return SC_ERROR_NOT_SUPPORTED;
	rv = iasecc_chipdoc_pkcs15_operation(p15, key, &operation);
	if (!rv)
		*key_out = key;
	return rv;
}

int
iasecc_chipdoc_pkcs15_activate(struct sc_pkcs15_card *p15)
{
#ifdef ENABLE_OPENSSL
	struct sc_pkcs15_object *key;
	int rv = iasecc_chipdoc_pkcs15_validate(p15, &key);
	return rv ? rv : iasecc_chipdoc_routing_install(p15, key);
#else
	(void)p15;
	return SC_ERROR_NOT_SUPPORTED;
#endif
}
