/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native post-bind activation of the explicit measured profile. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iasecc-chipdoc-routing.h"
#include "iasecc.h"
#include "internal.h"
#include "pkcs15.h"

/* Called only for the explicitly initialized candidate after native bind.
 * Enumerate public key/PIN metadata before installing restricted routing. */
int
iasecc_chipdoc_pkcs15_activate(struct sc_pkcs15_card *p15)
{
	struct sc_pkcs15_object *objects[32], *key = NULL;
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
	return iasecc_chipdoc_routing_install(p15, key);
}
