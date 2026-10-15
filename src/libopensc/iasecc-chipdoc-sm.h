/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef OPENSC_IASECC_CHIPDOC_SM_H
#define OPENSC_IASECC_CHIPDOC_SM_H
#include "iasecc-chipdoc-pkcs15.h"
#include "iasecc-chipdoc-transaction.h"
#include "opensc.h"
#include <stddef.h>

enum iasecc_chipdoc_mf_encoding { IASECC_CHIPDOC_MF_SHORT,
	IASECC_CHIPDOC_MF_EXTENDED };
/* Fixed control metadata only. No keys, card content, ciphertext or MAC. */
struct iasecc_chipdoc_channel_report {
	unsigned int commands;
	int transport, authenticated, reset_required;
	unsigned int sw;
};
/* No I/O. Supported crypto/context/transport only, not card authentication.
 * PIN status reflects a live managed proof, never a cached credential/count. */
int iasecc_chipdoc_channel_supported(struct sc_card *card);
int iasecc_chipdoc_channel_pin_status(struct sc_card *card, int *logged_in);

/* Explicit internal controller; not wired to public PKCS15/PKCS11 yet.
 * Adds exactly one sc_lock (nested callers retain theirs), resets once,
 * bootstraps the channel and selects MF short. Success keeps our lock until
 * transaction_close/logout/finish. Failed startup closes its own reservation.
 * Requires the strict native operation policy and opts.use_pin_cache=0;
 * the caller keeps caching disabled through authentication/signing.
 * Callers must serialize card APIs; this reservation does not add a mutex. */
int iasecc_chipdoc_transaction_begin(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_transaction_report *report);
/* Exactly one protected EMPTY VERIFY at MF, global reference1. No credential
 * data, no query replay, max-tries inference or authenticated-login claim.
 * Only observed63C7 advances this first profile; other authenticated counts
 * are reported then stop. Unauthenticated errors leave tries_left=-1. */
int iasecc_chipdoc_channel_query_pin(struct sc_card *card, unsigned int reference,
		int *tries_left, struct iasecc_chipdoc_channel_report *report);

/* One protected VERIFY from canonical OpenSC software-PIN arguments. Caller
 * owns and clears its input buffer; driver retains no credential. Measured
 * UTF8 profile initially admits printable ASCII6..14 only, without conversion
 * or padding. Requires managed PIN_AVAILABLE after authenticated63C7. Failed
 * transport/response drops channel; owner must close even after failure. */
int iasecc_chipdoc_channel_verify_pin(struct sc_card *card, const struct sc_pin_cmd_data *data,
		int *tries_left, struct iasecc_chipdoc_channel_report *report);

/* One measured protected AID selection after login, for the native PKCS15
 * use_key selection callback. Only the already validated profile AID is used. */
int iasecc_chipdoc_channel_select_application(struct sc_card *card,
		struct iasecc_chipdoc_channel_report *report);

/* Private typed SIGN/RSA2048/SHA256 operation. Selects the bound application
 * once after login (unless already selected under SM by the API above), then
 * MSE once; no public vtable wiring or generic IAS I/O.
 * Only the measured algorithm/key are accepted. Caller must close on failure. */
int iasecc_chipdoc_channel_set_security_env(struct sc_card *card, const struct sc_security_env *env,
		int se_num, struct iasecc_chipdoc_channel_report *report);
struct iasecc_chipdoc_signature_report {
	struct iasecc_chipdoc_channel_report channel;
	struct iasecc_chipdoc_transaction_report close;
};
/* One extended PSO with a SHA256 digest (exactly32 bytes), no DigestInfo/hash
 * conversion/retry/GET RESPONSE. Always closes after an accepted operation.
 * Returns256 only after authenticated success AND complete reset/unlock.
 * Output remains untouched on failure; caller owns/clears input and output. */
int iasecc_chipdoc_channel_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len,
		struct iasecc_chipdoc_signature_report *report);

enum iasecc_chipdoc_bootstrap_stage {
	IASECC_CHIPDOC_BOOTSTRAP_INPUT,
	IASECC_CHIPDOC_BOOTSTRAP_APPLICATION,
	IASECC_CHIPDOC_BOOTSTRAP_CONTROL,
	IASECC_CHIPDOC_BOOTSTRAP_READ,
	IASECC_CHIPDOC_BOOTSTRAP_PREPARE,
	IASECC_CHIPDOC_BOOTSTRAP_CHANNEL
};
struct iasecc_chipdoc_bootstrap_report {
	enum iasecc_chipdoc_bootstrap_stage stage;
	struct iasecc_chipdoc_channel_report channel;
};
/* Already decoded native PKCS#15 objects; explicit opt-in internal call.
 * No object discovery or remote reset, PIN, public driver binding or retry.
 * Caller invalidates local state and resets the card successfully under a
 * continuous outer lock BEFORE entry, then must reset/close before unlock
 * after ANY attempted command, including plain selection failures. Successful
 * bootstrap leaves a confirmed channel at SSC2 for this same transaction. */
int iasecc_chipdoc_channel_bootstrap(const struct sc_pkcs15_card *p15,
		const struct sc_pkcs15_object *key, struct iasecc_chipdoc_bootstrap_report *report);

/* Internal experimental API; not installed in the public driver operations.
 * Caller already holds an outer card lock, selected/validated ADF and D004,
 * read exactly137 bytes, and prepared the session using validated metadata.
 * Requires OpenSC's non-NULL OpenSSL3 libctx; borrows it without loading
 * providers or overriding properties. The context/providers must outlive the
 * card/channel. Replacing the context identity invalidates the session;
 * crypto denied by its policy fails without global-context fallback.
 * Any attempted setup or exchange must eventually be closed/reset under that
 * same lock, even after a local invalidation. No reset/PIN/follow-up here. */
int iasecc_chipdoc_channel_open(struct sc_card *card, const unsigned char *initial,
		size_t size, struct iasecc_chipdoc_channel_report *report);
int iasecc_chipdoc_channel_select_mf(struct sc_card *card,
		enum iasecc_chipdoc_mf_encoding encoding, struct iasecc_chipdoc_channel_report *report);
#endif
