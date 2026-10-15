/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Identity/structure/size match for the observed D004 control response.
 * Caller provides the OpenSC ASN.1 API; security attributes remain opaque. */
#ifndef JCOP4_DH_CONTROL_H
#define JCOP4_DH_CONTROL_H
#include "asn1.h"
static inline int
d004_control_matches_observation(const unsigned char *buf, size_t size)
{
	const unsigned char *p = buf, *value;
	size_t len, left;
	unsigned int cla, tag;
	int descriptor = 0, fid = 0, length = 0;
	if (!buf || !size || size > 256 ||
			sc_asn1_read_tag(&p, size, &cla, &tag, &len) < 0 || !p ||
			cla != 0x60 || (tag != 2 && tag != 15) || (size_t)(p - buf) + len != size)
		return 0;
	left = len;
	while (left) {
		size_t consumed;
		value = p;
		if (sc_asn1_read_tag(&value, left, &cla, &tag, &len) < 0 || !value ||
				(size_t)(value - p) > left || len > left - (size_t)(value - p))
			return 0;
		consumed = (size_t)(value - p) + len;
		switch (cla | tag) {
		case 0x82:
			if (descriptor++ || !len || (value[0] & 0x80) ||
					((value[0] & 0x3F) != 1 && (value[0] & 0x3F) != 9))
				return 0;
			break;
		case 0x83:
			if (fid++ || len != 2 || value[0] != 0xD0 || value[1] != 4)
				return 0;
			break;
		case 0x80: {
			size_t i, candidate = 0;
			if (length++ || !len || len > 4)
				return 0;
			for (i = 0; i < len; i++)
				candidate = (candidate << 8) | value[i];
			if (candidate != 137)
				return 0;
			break;
		}
			/* Match only; no security policy derived from other control fields. */
		}
		left -= consumed;
		p = value + len;
	}
	return descriptor == 1 && fid == 1 && length == 1;
}
#endif
