/* Temporary opt-in diagnostics: fixed events and numeric metadata only.
 * Never pass PINs, attributes, data buffers, lengths of PINs or APDUs.
 * The launcher supplies a private, pre-created file. No card commands are
 * issued here and logging failures must not affect the operation.
 */
#ifndef OPENSC_API_TRACE_H
#define OPENSC_API_TRACE_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

enum sc_api_trace_event {
	SC_API_OPEN_SESSION,
	SC_API_CLOSE_SESSION,
	SC_API_CLOSE_ALL_SESSIONS,
	SC_API_SESSION_INFO,
	SC_API_LOGIN,
	SC_API_LOGOUT,
	SC_API_SIGN_INIT,
	SC_API_SIGN,
	SC_API_SIGN_UPDATE,
	SC_API_SIGN_FINAL,
	SC_API_GET_ATTRIBUTE,
	SC_API_FIND_INIT,
	SC_API_PIN_STATUS,
	SC_API_SIGN_KEY,
	SC_API_KEY_SELECT,
	SC_API_KEY_MSE,
	SC_API_KEY_COMPUTE,
	SC_API_KEY_REVALIDATE,
	SC_API_CARD_SIGN_AT,
	SC_API_CARD_KEY_DOCP,
	SC_API_CARD_MSE,
	SC_API_SESSION_LOGIN_STATE,
	SC_API_TOKEN_INFO_BEGIN,
	SC_API_TOKEN_INFO,
	SC_API_TOKEN_PIN_STATUS,
	SC_API_CARD_SELECT,
	SC_API_CARD_PIN_INFO_BEGIN,
	SC_API_CARD_PIN_INFO,
	SC_API_CARD_LOCK,
	SC_API_CARD_RESET,
	SC_API_TOKEN_PIN_CACHED,
	SC_API_POST_LOGIN_STATUS_BEGIN,
	SC_API_POST_LOGIN_STATUS,
	SC_API_POST_LOGIN_SELECT_BEGIN,
	SC_API_POST_LOGIN_SELECT,
	SC_API_PIN_STATUS_IN_PLACE,
	SC_API_CARD_PIN_VERIFY,
	SC_API_CARD_PIN_VERIFY_CACHED,
	SC_API_SLOT_INFO_BEGIN,
	SC_API_SLOT_INFO,
	SC_API_CARD_PRESENCE,
	SC_API_SLOT_TOKEN_REMOVED,
	SC_API_PIN_APDU_BUILD,
	SC_API_PIN_TRANSMIT,
	SC_API_PRE_VERIFY_SELECT
};

static inline void
sc_api_metadata_trace(enum sc_api_trace_event event, unsigned long session,
		unsigned long rv, unsigned long a, unsigned long b)
{
	static const char *names[] = {
			"C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
			"C_Login", "C_Logout", "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal",
			"C_GetAttributeValue", "C_FindObjectsInit", "PIN_STATUS", "SIGN_KEY",
			"KEY_SELECT", "KEY_MSE", "KEY_COMPUTE", "KEY_REVALIDATE", "CARD_SIGN_AT",
			"CARD_KEY_DOCP", "CARD_MSE", "SESSION_LOGIN_STATE",
			"C_GetTokenInfo_BEGIN", "C_GetTokenInfo", "TOKEN_PIN_STATUS",
			"CARD_SELECT", "CARD_PIN_INFO_BEGIN", "CARD_PIN_INFO", "CARD_LOCK", "CARD_RESET",
			"TOKEN_PIN_CACHED", "POST_LOGIN_STATUS_BEGIN", "POST_LOGIN_STATUS",
			"POST_LOGIN_SELECT_BEGIN", "POST_LOGIN_SELECT", "PIN_STATUS_IN_PLACE",
			"CARD_PIN_VERIFY", "CARD_PIN_VERIFY_CACHED",
			"C_GetSlotInfo_BEGIN", "C_GetSlotInfo", "CARD_PRESENCE", "SLOT_TOKEN_REMOVED",
			"PIN_APDU_BUILD", "PIN_TRANSMIT", "PRE_VERIFY_SELECT"};
	int saved_errno = errno;
	const char *path = getenv("OPENSC_API_TRACE_FILE");
	FILE *file;

	if (path && *path && (unsigned int)event < sizeof(names) / sizeof(names[0])) {
		file = fopen(path, "a");
		if (file) {
			fprintf(file, "%s session=0x%lX rv=0x%lX a=0x%lX b=0x%lX\n",
					names[event], session, rv, a, b);
			fclose(file);
		}
	}
	errno = saved_errno;
}

#endif
