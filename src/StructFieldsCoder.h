#ifndef STRUCT_FIELDS_CODER_H
#define STRUCT_FIELDS_CODER_H

//================================================================================

#include "EUSignCP.h"
#include "AdditionalTypes.h"

//================================================================================

typedef struct {
	char*	*ppszFields;
	int		nCount;
	int		nIndex;
} STRUCT_FIELDS, *PSTRUCT_FIELDS;

//================================================================================

int Alloc(
	int						nCount,
	PSTRUCT_FIELDS			pFields);

void Free(
	PSTRUCT_FIELDS			pFields);

//--------------------------------------------------------------------------------

int Encode(
	PEU_SIGN_INFO			pInfo,
	PSTRUCT_FIELDS			pFields);

int Encode(
	PEU_TIME_INFO			pInfo,
	PSTRUCT_FIELDS			pFields);

int Encode(
	PEU_CERT_INFO			pInfo,
	PSTRUCT_FIELDS			pFields);

int Encode(
	PEU_CERT_INFO_EX		pInfo,
	PSTRUCT_FIELDS			pFields);

int Encode(
	PEU_CERT_OWNER_INFO		pInfo,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_USER_INFO			pUserInfo);

int Encode(
	PEU_REQUEST_INFO		pInfo,
	PSTRUCT_FIELDS			pFields);

int Encode(
	PEU_FILE_STORE_SETTINGS	pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_FILE_STORE_SETTINGS	pSettings);

int Encode(
	PEU_PROXY_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_PROXY_SETTINGS		pSettings);

int Encode(
	PEU_OCSP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_OCSP_SETTINGS		pSettings);

int Encode(
	PEU_TSP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_TSP_SETTINGS		pSettings);

int Encode(
	PEU_LDAP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_LDAP_SETTINGS		pSettings);

int Encode(
	PEU_CMP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_CMP_SETTINGS		pSettings);

int Encode(
	PEU_OCSP_ACCESS_INFO_MODE_SETTINGS	pSettings,
	PSTRUCT_FIELDS						pFields);

int Decode(
	PSTRUCT_FIELDS						pFields,
	PEU_OCSP_ACCESS_INFO_MODE_SETTINGS	pSettings);

int Encode(
	PEU_OCSP_ACCESS_INFO_SETTINGS	pSettings,
	PSTRUCT_FIELDS					pFields);

int Decode(
	PSTRUCT_FIELDS					pFields,
	PEU_OCSP_ACCESS_INFO_SETTINGS	pSettings);

int Encode(
	PEU_LOG_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_LOG_SETTINGS		pSettings);

int Encode(
	PEU_TSL_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_TSL_SETTINGS		pSettings);

int Encode(
	PEU_MODE_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_MODE_SETTINGS		pSettings);

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_KEY_MEDIA			pKeyMedia);

//================================================================================

#endif // STRUCT_FIELDS_CODER_H
