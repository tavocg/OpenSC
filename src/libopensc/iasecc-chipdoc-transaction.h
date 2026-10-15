/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef OPENSC_IASECC_CHIPDOC_TRANSACTION_H
#define OPENSC_IASECC_CHIPDOC_TRANSACTION_H
#include "iasecc.h"

enum iasecc_chipdoc_transaction_stage {
	IASECC_CHIPDOC_TX_INPUT,
	IASECC_CHIPDOC_TX_LOCK,
	IASECC_CHIPDOC_TX_RESET,
	IASECC_CHIPDOC_TX_BOOTSTRAP,
	IASECC_CHIPDOC_TX_MF,
	IASECC_CHIPDOC_TX_READY,
	IASECC_CHIPDOC_TX_CLOSE
};
struct iasecc_chipdoc_transaction_report {
	enum iasecc_chipdoc_transaction_stage stage;
	unsigned int commands;
	int bootstrap_stage, lock_result, initial_reset_result, final_reset_result, unlock_result;
	int initial_reset_attempted, close_attempted, final_reset_attempted, unlock_attempted;
	int lock_held, complete, reset_required;
};

static inline int
iasecc_chipdoc_transaction_owns(const struct sc_card *card,
		const struct iasecc_private_data *prv)
{
	const struct iasecc_chipdoc_transaction *t = &prv->chipdoc_transaction;
	return t->active && t->owned_lock && !t->lost && t->card == card &&
	       t->reader == card->reader && t->context == card->ctx && card->lock_count > 0;
}

/* Close only our extra lock, never a borrowed or reacquired transaction.
 * Clear crypto BEFORE reset, even when reset/unlock subsequently fails.
 * A failed/lost cleanup quarantines this card instance until reconnect.
 * No retry, PIN, APDU or reset of a transaction whose ownership was lost. */
static inline int
iasecc_chipdoc_transaction_close(struct sc_card *card,
		struct iasecc_chipdoc_transaction_report *report)
{
	struct iasecc_chipdoc_transaction_report local = {0};
	struct iasecc_private_data *prv = card ? card->drv_data : NULL;
	int owned, reset_required, result = SC_SUCCESS;
	if (!report)
		report = &local;
	memset(report, 0, sizeof(*report));
	report->stage = IASECC_CHIPDOC_TX_CLOSE;
	if (!prv)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!prv->chipdoc_transaction.active) {
		report->reset_required = prv->chipdoc_session.channel != NULL || prv->chipdoc_recovery_required;
		report->complete = !report->reset_required;
		return report->complete ? SC_SUCCESS : SC_ERROR_NOT_ALLOWED;
	}
	owned = iasecc_chipdoc_transaction_owns(card, prv);
	reset_required = prv->chipdoc_transaction.reset_required;
	report->close_attempted = 1;
	/* Detach ownership before cleanup/callbacks; repeated close cannot release
	 * another lock or issue a second reset. Permanent binding is preserved. */
	memset(&prv->chipdoc_transaction, 0, sizeof(prv->chipdoc_transaction));
	iasecc_chipdoc_invalidate_card(card);
	if (!owned) {
		prv->chipdoc_recovery_required = report->reset_required = 1;
		return SC_ERROR_CARD_RESET;
	}
	if (reset_required) {
		report->final_reset_attempted = 1;
		report->final_reset_result = sc_reset(card, 0);
		if (report->final_reset_result)
			result = report->final_reset_result;
	}
	report->unlock_attempted = 1;
	report->unlock_result = sc_unlock(card);
	if (!result && report->unlock_result)
		result = report->unlock_result;
	if (result)
		prv->chipdoc_recovery_required = 1;
	report->reset_required = prv->chipdoc_recovery_required;
	report->complete = !result && !report->reset_required;
	return result ? result : report->complete ? SC_SUCCESS
						  : SC_ERROR_NOT_ALLOWED;
}
#endif
