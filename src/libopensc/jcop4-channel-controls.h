/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef JCOP4_CHANNEL_CONTROLS_H
#define JCOP4_CHANNEL_CONTROLS_H
#include "jcop4-channel-messages.h"
/* Validate only MF identity/DF structure, never emit its raw control data. */
static inline int
jcop4_sm_mf_control(const unsigned char *data, size_t size)
{
	const unsigned char *value;
	size_t offset = 0, length;
	int fid = 0, descriptor = 0;
	if (!data || !size || size > 256)
		return 1;
	/* Canonical FCP62 or FCI6F; the latter can wrap exactly one FCP62. */
	unsigned char outer = data[0];
	if (outer != 0x62 && outer != 0x6F)
		return 1;
	if (jcop4_sm_take_tlv(data, size, &offset, outer, &value, &length) || offset != size)
		return 1;
	data = value;
	size = length;
	offset = 0;
	if (outer == 0x6F && size && data[0] == 0x62) {
		if (jcop4_sm_take_tlv(data, size, &offset, 0x62, &value, &length) || offset != size)
			return 1;
		data = value;
		size = length;
		offset = 0;
	}
	while (offset < size) {
		unsigned char tag = data[offset];
		if ((tag & 31) == 31 || jcop4_sm_take_tlv(data, size, &offset, tag, &value, &length))
			return 1;
		if (tag == 0x83 && (fid++ || length != 2 || value[0] != 0x3F || value[1]))
			return 1;
		if (tag == 0x82 && (descriptor++ || !length || length > 6 || (value[0] & 0x80) || (value[0] & 0x3F) != 0x38))
			return 1;
	}
	return fid != 1 || descriptor != 1;
}
#endif
