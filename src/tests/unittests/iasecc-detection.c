/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Exercise real driver dispatch and PKCS#15 bind with a simulated reader.
 * Fixtures contain public metadata only; no PIN, signing or channel setup.
 */
#include "torture.h"
#include "libopensc/internal.h"
#include "libopensc/iasecc.h"
#include "libopensc/pkcs15.h"
#include <openssl/opensslv.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

struct fixture {
	struct sc_context *ctx;
	struct sc_card *card;
	struct sc_pkcs15_card *p15;
	struct sc_reader reader;
	struct sc_reader_operations reader_ops;
	struct sc_card_driver *saved_drivers[SC_MAX_CARD_DRIVERS];
	struct sc_card_driver *iasecc;
	struct sc_card_driver fallback;
	struct sc_card_operations fallback_ops;
	unsigned int commands, metadata_commands, locks, unlocks, resets;
	unsigned int fail_step, sw, control_size, initial_size;
	int lock_error, unlock_error, bad_point;
	unsigned char curve, control[256], initial[137], directory[64];
	size_t directory_size, prkey_size, pin_size;
	unsigned char *prkey, *pin;
	int native_objects;
	const unsigned char *file_data;
	size_t file_size;
};

static const unsigned char tokeninfo[] = {0x30, 7, 2, 1, 0, 3, 2, 0, 0};
static const unsigned char empty_odf[] = {0, 0};
static const unsigned char native_odf[] = {
	0xA0, 6, 0x30, 4, 4, 2, 0x50, 0x33,
	0xA8, 6, 0x30, 4, 4, 2, 0x50, 0x34
};

static int select_public_file(struct sc_card *, const struct sc_path *, struct sc_file **);

static int transmit_metadata(struct fixture *f, struct sc_apdu *apdu)
{
	unsigned char fcp[] = {0x62, 10, 0x82, 1, 1, 0x83, 2, 0, 0, 0x80, 1, 0};
	struct sc_card view = {.reader = &f->reader, .lock_count = 1};
	struct sc_path path = {0};
	struct sc_file *file;
	size_t size;
	unsigned int offset;
	int rv;

	assert_true(++f->metadata_commands < 64);
	apdu->sw1 = 0x90;
	apdu->sw2 = 0;
	if (apdu->ins == 0xA4) {
		if (apdu->p1 == 4) {
			sc_format_path("5015", &path);
		} else {
			assert_true(apdu->datalen <= sizeof(path.value));
			memcpy(path.value, apdu->data, apdu->datalen);
			path.len = apdu->datalen;
		}
		rv = select_public_file(&view, &path, &file);
		if (rv) {
			apdu->sw1 = 0x6A;
			apdu->sw2 = 0x82;
			apdu->resplen = 0;
			return SC_SUCCESS;
		}
		assert_true(file->size <= 255);
		fcp[4] = file->type == SC_FILE_TYPE_DF ? 0x38 : 1;
		fcp[7] = path.value[path.len - 2];
		fcp[8] = path.value[path.len - 1];
		fcp[11] = (unsigned char)file->size;
		if (apdu->le) {
			assert_true(apdu->resplen >= sizeof(fcp));
			memcpy(apdu->resp, fcp, sizeof(fcp));
			apdu->resplen = sizeof(fcp);
		} else {
			apdu->resplen = 0;
		}
		sc_file_free(file);
	} else {
		assert_int_equal(apdu->ins, 0xB0); /* Public metadata reads only. */
		offset = (apdu->p1 << 8) | apdu->p2;
		assert_true(offset <= f->file_size);
		size = f->file_size - offset;
		if (size > apdu->le)
			size = apdu->le;
		assert_true(apdu->resplen >= size);
		memcpy(apdu->resp, f->file_data + offset, size);
		apdu->resplen = size;
	}
	return SC_SUCCESS;
}

static int reader_success(struct sc_reader *reader)
{
	(void)reader;
	return SC_SUCCESS;
}

static int reader_lock(struct sc_reader *reader)
{
	struct fixture *f = reader->drv_data;
	f->locks++;
	return f->lock_error;
}

static int reader_unlock(struct sc_reader *reader)
{
	struct fixture *f = reader->drv_data;
	f->unlocks++;
	return f->unlock_error;
}

static int reader_reset(struct sc_reader *reader, int cold)
{
	struct fixture *f = reader->drv_data;
	(void)cold;
	f->resets++;
	return SC_SUCCESS;
}

static int reader_transmit(struct sc_reader *reader, struct sc_apdu *apdu)
{
	struct fixture *f = reader->drv_data;
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	unsigned int flags = SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;

	assert_int_equal(apdu->cla, 0);
	if (f->commands == 3)
		return transmit_metadata(f, apdu);
	assert_int_equal(apdu->flags & flags, flags);
	assert_int_equal(f->locks, 1);
	assert_int_equal(f->unlocks, 0);
	switch (++f->commands) {
	case 1:
		assert_int_equal(apdu->ins, 0xA4);
		assert_int_equal(apdu->p1, 4);
		assert_int_equal(apdu->p2, 0x0C);
		assert_int_equal(apdu->lc, p->aid_len);
		assert_memory_equal(apdu->data, p->aid, p->aid_len);
		apdu->resplen = 0;
		break;
	case 2:
		assert_int_equal(apdu->ins, 0xA4);
		assert_int_equal(apdu->p1, 2);
		assert_int_equal(apdu->p2, 0);
		assert_int_equal(apdu->lc, 2);
		assert_memory_equal(apdu->data, "\xD0\x04", 2);
		assert_int_equal(apdu->le, 256);
		assert_true(apdu->resplen >= f->control_size);
		memcpy(apdu->resp, f->control, f->control_size);
		apdu->resplen = f->control_size;
		break;
	case 3:
		assert_int_equal(apdu->ins, 0xB0);
		assert_int_equal(apdu->p1, 0);
		assert_int_equal(apdu->p2, 0);
		assert_int_equal(apdu->lc, 0);
		assert_int_equal(apdu->le, 137);
		assert_true(apdu->resplen >= f->initial_size);
		memcpy(apdu->resp, f->initial, f->initial_size);
		apdu->resp[2] = f->curve;
		if (f->bad_point)
			memset(apdu->resp + 5, 0, 132);
		apdu->resplen = f->initial_size;
		break;
	default:
		fail_msg("Unexpected command during discovery (no PIN, setup or retry is allowed)");
	}
	if (f->commands == f->fail_step) {
		if (!f->sw)
			return SC_ERROR_TRANSMIT_FAILED;
		apdu->sw1 = f->sw >> 8;
		apdu->sw2 = f->sw & 0xFF;
	} else {
		apdu->sw1 = 0x90;
		apdu->sw2 = 0;
	}
	return SC_SUCCESS;
}

static int fallback_match(struct sc_card *card)
{
	card->type = -1;
	return 1;
}

static int card_success(struct sc_card *card)
{
	(void)card;
	return SC_SUCCESS;
}

static int select_public_file(struct sc_card *card, const struct sc_path *path, struct sc_file **out)
{
	struct fixture *f = card->reader->drv_data;
	unsigned int fid = path->len >= 2 ? (path->value[path->len - 2] << 8) | path->value[path->len - 1] : 0;

	assert_true(card->lock_count > 0);
	if (out)
		*out = NULL;
	switch (fid) {
	case 0x5015:
		f->file_data = NULL;
		f->file_size = 0;
		break;
	case 0x3F00:
		f->file_data = NULL;
		f->file_size = 0;
		break;
	case 0x2F00:
		f->file_data = f->directory;
		f->file_size = f->directory_size;
		break;
	case 0x5032:
		f->file_data = tokeninfo;
		f->file_size = sizeof(tokeninfo);
		break;
	case 0x5031:
		f->file_data = f->native_objects ? native_odf : empty_odf;
		f->file_size = f->native_objects ? sizeof(native_odf) : sizeof(empty_odf);
		break;
	case 0x5033:
		f->file_data = f->prkey;
		f->file_size = f->prkey_size;
		break;
	case 0x5034:
		f->file_data = f->pin;
		f->file_size = f->pin_size;
		break;
	default:
		return SC_ERROR_FILE_NOT_FOUND;
	}
	if (out) {
		*out = sc_file_new();
		assert_non_null(*out);
		(*out)->path = *path;
		(*out)->size = f->file_size;
		(*out)->type = fid == 0x5015 ? SC_FILE_TYPE_DF : SC_FILE_TYPE_WORKING_EF;
		(*out)->ef_structure = SC_FILE_EF_TRANSPARENT;
	}
	return SC_SUCCESS;
}

static void encode_objects(struct fixture *f, unsigned int key_reference, unsigned int bits,
		unsigned int pin_reference)
{
	struct sc_pkcs15_prkey_info info = {0};
	struct sc_pkcs15_auth_info auth = {0};
	struct sc_pkcs15_object key = {0}, pin = {0};

	info.native = 1;
	info.key_reference = key_reference;
	info.modulus_length = bits;
	info.usage = SC_PKCS15_PRKEY_USAGE_SIGN;
	info.id.len = 1;
	info.id.value[0] = 1;
	info.path.count = -1;
	key.type = SC_PKCS15_TYPE_PRKEY_RSA;
	key.data = &info;
	key.auth_id = info.id;
	auth.auth_id = info.id;
	auth.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth.auth_method = SC_AC_CHV;
	auth.attrs.pin.reference = pin_reference;
	auth.attrs.pin.min_length = 6;
	auth.attrs.pin.max_length = auth.attrs.pin.stored_length = 14;
	auth.attrs.pin.type = SC_PKCS15_PIN_TYPE_UTF8;
	auth.attrs.pin.flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED;
	auth.path.count = -1;
	pin.type = SC_PKCS15_TYPE_AUTH_PIN;
	pin.data = &auth;
	free(f->prkey);
	free(f->pin);
	f->prkey = f->pin = NULL;
	assert_int_equal(sc_pkcs15_encode_prkdf_entry(f->ctx, &key, &f->prkey, &f->prkey_size), SC_SUCCESS);
	assert_int_equal(sc_pkcs15_encode_aodf_entry(f->ctx, &pin, &f->pin, &f->pin_size), SC_SUCCESS);
}

static void directory_aid(struct fixture *f, const unsigned char *aid, size_t size)
{
	assert_true(size + 10 <= sizeof(f->directory));
	f->directory_size = size + 10;
	f->directory[0] = 0x61;
	f->directory[1] = (unsigned char)(size + 8);
	f->directory[2] = 0x4F;
	f->directory[3] = (unsigned char)size;
	memcpy(f->directory + 4, aid, size);
	memcpy(f->directory + 4 + size, "\x51\x04\x3F\x00\x50\x15", 6);
}

static int read_public_file(struct sc_card *card, unsigned int offset, unsigned char *out,
		size_t size, unsigned long *flags)
{
	struct fixture *f = card->reader->drv_data;
	(void)flags;
	assert_true(card->lock_count > 0);
	assert_true(offset <= f->file_size);
	if (size > f->file_size - offset)
		size = f->file_size - offset;
	memcpy(out, f->file_data + offset, size);
	return (int)size;
}

static void configure(struct fixture *f, const char *text)
{
	scconf_free(f->ctx->conf);
	f->ctx->conf = NULL;
	memset(f->ctx->conf_blocks, 0, sizeof(f->ctx->conf_blocks));
	if (text) {
		scconf_block **blocks;
		f->ctx->conf = scconf_new(NULL);
		assert_non_null(f->ctx->conf);
		assert_int_equal(scconf_parse_string(f->ctx->conf, text), 1);
		blocks = scconf_find_blocks(f->ctx->conf, NULL, "app", "default");
		assert_non_null(blocks);
		f->ctx->conf_blocks[0] = blocks[0];
		free(blocks);
		assert_non_null(f->ctx->conf_blocks[0]);
	}
}

static int setup(void **state)
{
	struct fixture *f = calloc(1, sizeof(*f));
	const struct iasecc_chipdoc_profile *p = iasecc_chipdoc_profile(IASECC_CHIPDOC_CR_RSA2048);
	const unsigned char control[] = {0x62, 10, 0x82, 1, 1, 0x83, 2, 0xD0, 4, 0x80, 1, 137};
	EC_GROUP *group;
	unsigned char point[133];

	assert_non_null(f);
	assert_int_equal(sc_establish_context(&f->ctx, "iasecc-detection"), SC_SUCCESS);
	f->ctx->debug = 0;
	configure(f, NULL);
	memcpy(f->saved_drivers, f->ctx->card_drivers, sizeof(f->saved_drivers));
	for (unsigned int i = 0; f->ctx->card_drivers[i]; i++)
		if (!strcmp(f->ctx->card_drivers[i]->short_name, "iasecc"))
			f->iasecc = f->ctx->card_drivers[i];
	assert_non_null(f->iasecc);
	f->fallback_ops = *sc_get_iso7816_driver()->ops;
	f->fallback_ops.match_card = fallback_match;
	f->fallback_ops.init = card_success;
	f->fallback_ops.finish = card_success;
	f->fallback_ops.select_file = select_public_file;
	f->fallback_ops.read_binary = read_public_file;
	f->fallback.name = f->fallback.short_name = "test-fallback";
	f->fallback.ops = &f->fallback_ops;
	memset(f->ctx->card_drivers, 0, sizeof(f->ctx->card_drivers));
	f->ctx->card_drivers[0] = f->iasecc;
	f->ctx->card_drivers[1] = &f->fallback;
	f->reader_ops.connect = f->reader_ops.disconnect = reader_success;
	f->reader_ops.transmit = reader_transmit;
	f->reader_ops.lock = reader_lock;
	f->reader_ops.unlock = reader_unlock;
	f->reader_ops.reset = reader_reset;
	f->reader.ctx = f->ctx;
	f->reader.ops = &f->reader_ops;
	f->reader.name = "Simulated IAS/ECC reader";
	f->reader.drv_data = f;
	f->reader.active_protocol = SC_PROTO_T1;
	f->reader.max_send_size = 255;
	f->reader.max_recv_size = 512;
	memcpy(f->reader.atr.value, p->atr, p->atr_len);
	f->reader.atr.len = p->atr_len;
	memcpy(f->control, control, sizeof(control));
	f->control_size = sizeof(control);
	f->initial_size = sizeof(f->initial);
	f->curve = p->curve_selector;
	directory_aid(f, p->aid, p->aid_len);
	encode_objects(f, 0x91, 2048, 1);
	f->native_objects = 1;
	/* The curve generator is a deterministic public fixture, not a keypair. */
	group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	assert_non_null(group);
	assert_int_equal(EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
			POINT_CONVERSION_UNCOMPRESSED, point, sizeof(point), NULL), sizeof(point));
	memcpy(f->initial + 5, point + 1, 132);
	EC_GROUP_free(group);
	*state = f;
	return 0;
}

static int teardown(void **state)
{
	struct fixture *f = *state;
	if (f->p15)
		sc_pkcs15_unbind(f->p15);
	if (f->card)
		sc_disconnect_card(f->card);
	memcpy(f->ctx->card_drivers, f->saved_drivers, sizeof(f->saved_drivers));
	assert_int_equal(sc_release_context(f->ctx), SC_SUCCESS);
	free(f->prkey);
	free(f->pin);
	free(f);
	return 0;
}

static void connect_as(struct fixture *f, int chipdoc, unsigned int commands)
{
	assert_int_equal(sc_connect_card(&f->reader, &f->card), SC_SUCCESS);
	assert_ptr_equal(f->card->driver, chipdoc ? f->iasecc : &f->fallback);
	assert_int_equal(f->commands, commands);
	assert_int_equal(f->resets, 0);
	assert_int_equal(f->card->lock_count, 0);
	assert_int_equal(f->locks, f->unlocks);
	if (!chipdoc) {
		assert_null(f->card->drv_data);
		assert_int_equal(f->card->algorithm_count, 0);
		assert_false(f->card->caps & SC_CARD_CAP_APDU_EXT);
	}
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
static void detect_jcop4(void **state)
{
	struct fixture *f = *state;
	connect_as(f, 1, 3);
	assert_true(iasecc_chipdoc_configured(f->card));
	assert_int_equal(f->card->type, SC_CARD_TYPE_IASECC_CHIPDOC);
	assert_int_equal(f->card->algorithm_count, 1);
	assert_int_equal(f->card->algorithms[0].key_length, 2048);
	assert_int_equal(f->card->algorithms[0].flags,
			SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256);
	assert_true(f->metadata_commands > 0);
	/* Discovery must not retain temporary applications, objects or routing. */
	assert_int_equal(f->card->app_count, -1);
	assert_null(((struct iasecc_private_data *)f->card->drv_data)->chipdoc_routing);
}

static void bind_jcop4(void **state)
{
	struct fixture *f = *state;
	connect_as(f, 1, 3);
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_false(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_false(f->p15->opts.use_pin_cache);
	assert_int_equal(f->p15->opts.use_file_cache, SC_PKCS15_OPTS_CACHE_NO_FILES);
	assert_non_null(((struct iasecc_private_data *)f->card->drv_data)->chipdoc_routing);
	assert_int_equal(f->commands, 3);
	assert_int_equal(f->resets, 0);
}

static void reject_missing_key(void **state)
{
	struct fixture *f = *state;
	f->native_objects = 0;
	connect_as(f, 0, 3);
	assert_true(f->metadata_commands > 0);
}

static void reject_other_key(void **state)
{
	struct fixture *f = *state;
	encode_objects(f, 0x92, 2048, 1);
	connect_as(f, 0, 3);
}

static void reject_other_key_size(void **state)
{
	struct fixture *f = *state;
	encode_objects(f, 0x91, 3072, 1);
	connect_as(f, 0, 3);
}

static void reject_other_pin(void **state)
{
	struct fixture *f = *state;
	encode_objects(f, 0x91, 2048, 2);
	connect_as(f, 0, 3);
}

static void reject_other_application(void **state)
{
	struct fixture *f = *state;
	f->directory[4] ^= 1;
	connect_as(f, 0, 3);
}

static void reject_duplicate_application(void **state)
{
	struct fixture *f = *state;
	assert_true(2 * f->directory_size <= sizeof(f->directory));
	memcpy(f->directory + f->directory_size, f->directory, f->directory_size);
	f->directory_size *= 2;
	connect_as(f, 0, 3);
}

static void reject_duplicate_key(void **state)
{
	struct fixture *f = *state;
	unsigned char *two = realloc(f->prkey, 2 * f->prkey_size);
	assert_non_null(two);
	f->prkey = two;
	memcpy(f->prkey + f->prkey_size, f->prkey, f->prkey_size);
	f->prkey_size *= 2;
	connect_as(f, 0, 3);
}

static void reject_duplicate_pin(void **state)
{
	struct fixture *f = *state;
	unsigned char *two = realloc(f->pin, 2 * f->pin_size);
	assert_non_null(two);
	f->pin = two;
	memcpy(f->pin + f->pin_size, f->pin, f->pin_size);
	f->pin_size *= 2;
	connect_as(f, 0, 3);
}

static void reject_shared_atr(void **state)
{
	struct fixture *f = *state;
	f->fail_step = 1;
	f->sw = 0x6A82;
	connect_as(f, 0, 1);
}

static void reject_control(void **state)
{
	struct fixture *f = *state;
	f->control[7] = 0xD1;
	connect_as(f, 0, 2);
}

static void reject_control_size(void **state)
{
	struct fixture *f = *state;
	f->control[11] = 136;
	connect_as(f, 0, 2);
}

static void reject_curve(void **state)
{
	struct fixture *f = *state;
	f->curve = 0x18; /* The observed selector is decimal 18, not hexadecimal. */
	connect_as(f, 0, 3);
}

static void reject_short_read(void **state)
{
	struct fixture *f = *state;
	f->initial_size--;
	connect_as(f, 0, 3);
}

static void reject_point(void **state)
{
	struct fixture *f = *state;
	f->bad_point = 1;
	connect_as(f, 0, 3);
	assert_int_equal(ERR_peek_error(), 0);
}

static void preserve_crypto_errors(void **state)
{
	struct fixture *f = *state;
	unsigned long previous;
	ERR_raise(ERR_LIB_USER, 1);
	previous = ERR_peek_error();
	assert_true(previous != 0);
	f->bad_point = 1;
	connect_as(f, 0, 3);
	assert_int_equal(ERR_get_error(), previous);
	assert_int_equal(ERR_get_error(), 0);
}

static void reject_reader_lock(void **state)
{
	struct fixture *f = *state;
	f->lock_error = SC_ERROR_READER_LOCKED;
	assert_int_equal(sc_connect_card(&f->reader, &f->card), SC_SUCCESS);
	assert_ptr_equal(f->card->driver, &f->fallback);
	assert_int_equal(f->locks, 1);
	assert_int_equal(f->unlocks, 0);
	assert_int_equal(f->commands, 0);
	assert_int_equal(f->resets, 0);
}

static void reject_reader_unlock(void **state)
{
	struct fixture *f = *state;
	f->unlock_error = SC_ERROR_READER_LOCKED;
	connect_as(f, 0, 3);
}

static void reject_transport(void **state)
{
	struct fixture *f = *state;
	/* The public dispatcher must not retry failed discovery commands. */
	for (unsigned int step = 1; step <= 3; step++) {
		f->fail_step = step;
		connect_as(f, 0, step);
		sc_disconnect_card(f->card);
		f->card = NULL;
		f->commands = f->locks = f->unlocks = 0;
	}
}

static void reject_retry_status(void **state)
{
	struct fixture *f = *state;
	f->fail_step = 1;
	f->sw = 0x6C00;
	connect_as(f, 0, 1);
}

static void reject_get_response(void **state)
{
	struct fixture *f = *state;
	f->fail_step = 1;
	f->sw = 0x6101;
	connect_as(f, 0, 1);
}

static void explicit_profile(void **state)
{
	struct fixture *f = *state;
	configure(f, "app default { card_driver iasecc { chipdoc_profile = cr-rsa2048; } }");
	connect_as(f, 1, 0); /* Existing opt-in remains available without a new probe. */
}

static void explicit_auto(void **state)
{
	struct fixture *f = *state;
	configure(f, "app default { card_driver iasecc { chipdoc_profile = auto; } }");
	connect_as(f, 1, 3);
}
#endif

static void unrelated_atr(void **state)
{
	struct fixture *f = *state;
	f->reader.atr.len = 2;
	f->reader.atr.value[0] = 0x3B;
	f->reader.atr.value[1] = 0;
	connect_as(f, 0, 0);
}

static void disabled_profile(void **state)
{
	struct fixture *f = *state;
	configure(f, "app default { card_driver iasecc { chipdoc_profile = none; } }");
	connect_as(f, 0, 0);
}

static void unsupported_transport(void **state)
{
	struct fixture *f = *state;
	f->reader.max_recv_size = 256;
	connect_as(f, 0, 0);
}

static void unsupported_protocol(void **state)
{
	struct fixture *f = *state;
	f->reader.active_protocol = SC_PROTO_T0;
	connect_as(f, 0, 0);
}

static void prepare_bind(struct fixture *f, int type, int generic)
{
	const unsigned char aid[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50,
		0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63};
	/* Obtain a normal core-owned card; substitute only its file I/O. The real
	 * PKCS#15 parser and IAS/ECC emulator operate on the public fixtures. */
	f->reader.atr.len = 2;
	f->reader.atr.value[1] = 0;
	assert_int_equal(sc_connect_card(&f->reader, &f->card), SC_SUCCESS);
	f->card->driver = f->iasecc;
	f->card->type = type;
	f->native_objects = 0;
	directory_aid(f, aid, sizeof(aid));
	if (!generic)
		f->directory[4] = 0xA0;
}

static void bind_jcop3(void **state)
{
	struct fixture *f = *state;
	prepare_bind(f, SC_CARD_TYPE_IASECC_AMOS, 1);
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_non_null(f->p15->app);
	assert_true(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_non_null(f->p15->ops.parse_df);
	assert_false(f->p15->opts.use_pin_cache);
	assert_int_equal(f->p15->opts.use_file_cache, SC_PKCS15_OPTS_CACHE_NO_FILES);
	assert_int_equal(f->commands, 0);
}

static void bind_other_application(void **state)
{
	struct fixture *f = *state;
	prepare_bind(f, SC_CARD_TYPE_IASECC_AMOS, 0);
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_false(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_true(f->p15->opts.use_pin_cache);
}

static void bind_other_iasecc(void **state)
{
	struct fixture *f = *state;
	prepare_bind(f, SC_CARD_TYPE_IASECC_SAGEM, 1);
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_false(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_true(f->p15->opts.use_pin_cache);
}

static void bind_other_driver(void **state)
{
	struct fixture *f = *state;
	prepare_bind(f, SC_CARD_TYPE_IASECC_AMOS, 1);
	f->card->driver = &f->fallback;
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_false(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_true(f->p15->opts.use_pin_cache);
}

static void bind_explicit_options(void **state)
{
	struct fixture *f = *state;
	configure(f, "app default { framework pkcs15 { use_pin_caching = yes; try_emulation_first = no; } }");
	prepare_bind(f, SC_CARD_TYPE_IASECC_AMOS, 1);
	assert_int_equal(sc_pkcs15_bind(f->card, NULL, &f->p15), SC_SUCCESS);
	assert_false(f->p15->flags & SC_PKCS15_CARD_FLAG_EMULATED);
	assert_true(f->p15->opts.use_pin_cache);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		cmocka_unit_test_setup_teardown(detect_jcop4, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_jcop4, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_missing_key, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_other_key, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_other_key_size, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_other_pin, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_other_application, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_duplicate_application, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_duplicate_key, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_duplicate_pin, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_shared_atr, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_control, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_control_size, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_curve, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_short_read, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_point, setup, teardown),
		cmocka_unit_test_setup_teardown(preserve_crypto_errors, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_reader_lock, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_reader_unlock, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_transport, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_retry_status, setup, teardown),
		cmocka_unit_test_setup_teardown(reject_get_response, setup, teardown),
		cmocka_unit_test_setup_teardown(explicit_profile, setup, teardown),
		cmocka_unit_test_setup_teardown(explicit_auto, setup, teardown),
#endif
		cmocka_unit_test_setup_teardown(unrelated_atr, setup, teardown),
		cmocka_unit_test_setup_teardown(disabled_profile, setup, teardown),
		cmocka_unit_test_setup_teardown(unsupported_transport, setup, teardown),
		cmocka_unit_test_setup_teardown(unsupported_protocol, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_jcop3, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_other_application, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_other_iasecc, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_other_driver, setup, teardown),
		cmocka_unit_test_setup_teardown(bind_explicit_options, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
