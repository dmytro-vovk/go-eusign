//================================================================================

#include <stdio.h>
#include "Module.h"
#include "StringCoder.h"
#include "StructFieldsCoder.h"

//================================================================================

#define SIGN_INFO_FIELDS_COUNT						21
#define TIME_INFO_FIELDS_COUNT						6
#define CERT_OWNER_INFO_FIELDS_COUNT				18
#define CERT_INFO_FIELDS_COUNT						45
#define CERT_INFO_EX_FIELDS_COUNT					61
#define REQUEST_INFO_FIELDS_COUNT					49

#define FILE_STORE_SETTINGS_FIELDS_COUNT			8
#define PROXY_SETTINGS_FIELDS_COUNT					7
#define OCSP_SETTINGS_FIELDS_COUNT					4
#define TSP_SETTINGS_FIELDS_COUNT					3
#define LDAP_SETTINGS_FIELDS_COUNT					6
#define CMP_SETTINGS_FIELDS_COUNT					4
#define OCSP_ACCESS_INFO_MODE_SETTINGS_FIELDS_COUNT	1
#define OCSP_ACCESS_INFO_SETTINGS_FIELDS_COUNT		3
#define LOG_SETTINGS_FIELDS_COUNT					5
#define MODE_SETTINGS_FIELDS_COUNT					1

#define MAX_INT_STR_LENGTH							10
#define MAX_SYSTEMTIME_STR_LENGTH					19

//================================================================================

int Alloc(
	int					nCount,
	PSTRUCT_FIELDS		pFields)
{
	if (!pFields)
		return FALSE;

	pFields->ppszFields = new char*[nCount];
	if (!pFields->ppszFields)
		return FALSE;

	memset(pFields->ppszFields, 0, nCount * sizeof(char*));
	pFields->nCount = nCount;
	pFields->nIndex = 0;

	return TRUE;
}

//--------------------------------------------------------------------------------

void Free(
	PSTRUCT_FIELDS		pFields)
{
	if (!pFields || !pFields->ppszFields)
		return;

	for (int nI = 0; nI < pFields->nCount; nI++)
	{
		if (pFields->ppszFields[nI])
			delete[] pFields->ppszFields[nI];
	}

	delete[] pFields->ppszFields;

	memset(pFields, 0, sizeof(STRUCT_FIELDS));
}

//--------------------------------------------------------------------------------

int Add(
	const char*		szValue,
	PSTRUCT_FIELDS	pFields)
{
	char*			pszVal;

	if (!pFields ||
		(pFields->nIndex >= pFields->nCount))
	{
		return FALSE;
	}

	if (!ConvertString(
			CP_ACP, szValue,
			CP_UTF8, &pszVal))
	{
		return FALSE;
	}

	pFields->ppszFields[pFields->nIndex] = pszVal;
	pFields->nIndex++;

	return TRUE;
}

//--------------------------------------------------------------------------------

int Get(
	PSTRUCT_FIELDS	pFields,
	char*			pszValue,
	int				nValueMaxSize)
{
	char*			pszTmp;
	int				nTmpSize;

	if (!pFields && (pFields->nIndex >= pFields->nCount))
		return FALSE;

	if (pszValue == NULL)
		return FALSE;

	if (!ConvertString(
			CP_UTF8, pFields->ppszFields[pFields->nIndex],
			CP_ACP, &pszTmp))
	{
		return FALSE;
	}

	nTmpSize = strlen(pszTmp) + 1;
	if (nTmpSize > nValueMaxSize)
	{
		delete[] pszTmp;
		return FALSE;
	}

	strcpy(pszValue, pszTmp);
	delete[] pszTmp;

	pFields->nIndex++;

	return TRUE;
}

//--------------------------------------------------------------------------------

int Add(
	int				nValue,
	PSTRUCT_FIELDS	pFields)
{
	char			szValue[MAX_INT_STR_LENGTH + 1];

	sprintf(szValue, "%d", nValue);

	return Add(szValue, pFields);
}

//--------------------------------------------------------------------------------

int Get(
	PSTRUCT_FIELDS	pFields,
	int				*pnValue)
{
	char			szValue[MAX_INT_STR_LENGTH + 1];
	int				nValue;

	if (!Get(pFields, szValue, sizeof(szValue)))
		return FALSE;

	if (sscanf(szValue, "%d", &nValue) != 1)
		return FALSE;

	if (pnValue)
		*pnValue = nValue;

	return TRUE;
}

//--------------------------------------------------------------------------------

int Add(
	unsigned long	dwValue,
	PSTRUCT_FIELDS	pFields)
{
	return Add((int) dwValue, pFields);
}

//--------------------------------------------------------------------------------

int Get(
	PSTRUCT_FIELDS	pFields,
	unsigned long	*pdwValue)
{
	int				nValue;

	if (!Get(pFields, &nValue))
		return FALSE;

	if (pdwValue)
		*pdwValue = nValue;

	return TRUE;
}

//--------------------------------------------------------------------------------

int Add(
	PSYSTEMTIME		pValue,
	PSTRUCT_FIELDS	pFields)
{
	char			szValue[MAX_SYSTEMTIME_STR_LENGTH + 1];

	memset(szValue, 0, MAX_SYSTEMTIME_STR_LENGTH + 1);

	sprintf(szValue,
		"%.2hu.%.2hu.%.4hu %.2hu:%.2hu:%.2hu",
		pValue->wDay, pValue->wMonth, pValue->wYear,
		pValue->wHour, pValue->wMinute, pValue->wSecond);

	return Add(szValue, pFields);
}

//--------------------------------------------------------------------------------

int Get(
	PSTRUCT_FIELDS	pFields,
	PSYSTEMTIME		pValue)
{
	char			szValue[MAX_SYSTEMTIME_STR_LENGTH + 1];
	SYSTEMTIME		stValue;

	if (!Get(pFields, szValue, sizeof(szValue)))
		return FALSE;

	if (sscanf(szValue, "%hu.%hu.%hu %hu:%hu:%hu",
			&stValue.wDay, &stValue.wMonth, &stValue.wYear,
			&stValue.wHour, &stValue.wMinute, &stValue.wSecond) != 6)
	{
		return FALSE;
	}

	if (pValue)
		memcpy(pValue, &stValue, sizeof(SYSTEMTIME));

	return TRUE;
}

//--------------------------------------------------------------------------------

int Add(
	PEU_BYTE_ARRAY	pValue,
	PSTRUCT_FIELDS	pFields)
{
	unsigned long	dwError;
	char			*pszValue;

	dwError = BASE64Encode(
		pValue->pbData, pValue->dwDataLength, &pszValue);
	if (dwError != EU_ERROR_NONE)
		return FALSE;

	if (!Add(pszValue, pFields))
	{
		FreeMemory((unsigned char*) pszValue);

		return FALSE;
	}

	FreeMemory((unsigned char*) pszValue);

	return TRUE;
}

//==============================================================================

int Encode(
	PEU_SIGN_INFO		pInfo,
	PSTRUCT_FIELDS		pFields)
{
	if (!Alloc(SIGN_INFO_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->bFilled, pFields) ||
		!Add(pInfo->pszIssuer, pFields) ||
		!Add(pInfo->pszIssuerCN, pFields) ||
		!Add(pInfo->pszSerial, pFields) ||
		!Add(pInfo->pszSubject, pFields) ||
		!Add(pInfo->pszSubjCN, pFields) ||
		!Add(pInfo->pszSubjOrg, pFields) ||
		!Add(pInfo->pszSubjOrgUnit, pFields) ||
		!Add(pInfo->pszSubjTitle, pFields) ||
		!Add(pInfo->pszSubjState, pFields) ||
		!Add(pInfo->pszSubjLocality, pFields) ||
		!Add(pInfo->pszSubjFullName, pFields) ||
		!Add(pInfo->pszSubjAddress, pFields) ||
		!Add(pInfo->pszSubjPhone, pFields) ||
		!Add(pInfo->pszSubjEMail, pFields) ||
		!Add(pInfo->pszSubjDNS, pFields) ||
		!Add(pInfo->pszSubjEDRPOUCode, pFields) ||
		!Add(pInfo->pszSubjDRFOCode, pFields) ||
		!Add(pInfo->bTimeAvail, pFields) ||
		!Add(pInfo->bTimeStamp, pFields) ||
		!Add(&pInfo->Time, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_TIME_INFO		pInfo,
	PSTRUCT_FIELDS		pFields)
{
	if (!Alloc(TIME_INFO_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->dwVersion, pFields) ||
		!Add(pInfo->bTimeAvail, pFields) ||
		!Add(pInfo->bTimeStamp, pFields) ||
		!Add(&pInfo->Time, pFields) ||
		!Add(pInfo->bSignTimeStampAvail, pFields) ||
		!Add(&pInfo->SignTimeStamp, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_CERT_INFO		pInfo,
	PSTRUCT_FIELDS		pFields)
{
	if (!Alloc(CERT_INFO_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->bFilled, pFields) ||
		!Add(pInfo->dwVersion, pFields) ||
		!Add(pInfo->pszIssuer, pFields) ||
		!Add(pInfo->pszIssuerCN, pFields) ||
		!Add(pInfo->pszSerial, pFields) ||
		!Add(pInfo->pszSubject, pFields) ||
		!Add(pInfo->pszSubjCN, pFields) ||
		!Add(pInfo->pszSubjOrg, pFields) ||
		!Add(pInfo->pszSubjOrgUnit, pFields) ||
		!Add(pInfo->pszSubjTitle, pFields) ||
		!Add(pInfo->pszSubjState, pFields) ||
		!Add(pInfo->pszSubjLocality, pFields) ||
		!Add(pInfo->pszSubjFullName, pFields) ||
		!Add(pInfo->pszSubjAddress, pFields) ||
		!Add(pInfo->pszSubjPhone, pFields) ||
		!Add(pInfo->pszSubjEMail, pFields) ||
		!Add(pInfo->pszSubjDNS, pFields) ||
		!Add(pInfo->pszSubjEDRPOUCode, pFields) ||
		!Add(pInfo->pszSubjDRFOCode, pFields) ||
		!Add(pInfo->pszSubjNBUCode, pFields) ||
		!Add(pInfo->pszSubjSPFMCode, pFields) ||
		!Add(pInfo->pszSubjOCode, pFields) ||
		!Add(pInfo->pszSubjOUCode, pFields) ||
		!Add(pInfo->pszSubjUserCode, pFields) ||
		!Add(&pInfo->stCertBeginTime, pFields) ||
		!Add(&pInfo->stCertEndTime, pFields) ||
		!Add(pInfo->bPrivKeyTimes, pFields) ||
		!Add(&pInfo->stPrivKeyBeginTime, pFields) ||
		!Add(&pInfo->stPrivKeyEndTime, pFields) ||
		!Add(pInfo->dwPublicKeyBits, pFields) ||
		!Add(pInfo->pszPublicKey, pFields) ||
		!Add(pInfo->pszPublicKeyID, pFields) ||
		!Add(pInfo->bECDHPublicKey, pFields) ||
		!Add(pInfo->dwECDHPublicKeyBits, pFields) ||
		!Add(pInfo->pszECDHPublicKey, pFields) ||
		!Add(pInfo->pszECDHPublicKeyID, pFields) ||
		!Add(pInfo->pszIssuerPublicKeyID, pFields) ||
		!Add(pInfo->pszKeyUsage, pFields) ||
		!Add(pInfo->pszExtKeyUsages, pFields) ||
		!Add(pInfo->pszPolicies, pFields) ||
		!Add(pInfo->pszCRLDistribPoint1, pFields) ||
		!Add(pInfo->pszCRLDistribPoint2, pFields) ||
		!Add(pInfo->bPowerCert, pFields) ||
		!Add(pInfo->bSubjType, pFields) ||
		!Add(pInfo->bSubjCA, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_CERT_INFO_EX	pInfo,
	PSTRUCT_FIELDS		pFields)
{
	if (!Alloc(CERT_INFO_EX_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->bFilled, pFields) ||
		!Add(pInfo->dwVersion, pFields) ||
		!Add(pInfo->pszIssuer, pFields) ||
		!Add(pInfo->pszIssuerCN, pFields) ||
		!Add(pInfo->pszSerial, pFields) ||
		!Add(pInfo->pszSubject, pFields) ||
		!Add(pInfo->pszSubjCN, pFields) ||
		!Add(pInfo->pszSubjOrg, pFields) ||
		!Add(pInfo->pszSubjOrgUnit, pFields) ||
		!Add(pInfo->pszSubjTitle, pFields) ||
		!Add(pInfo->pszSubjState, pFields) ||
		!Add(pInfo->pszSubjLocality, pFields) ||
		!Add(pInfo->pszSubjFullName, pFields) ||
		!Add(pInfo->pszSubjAddress, pFields) ||
		!Add(pInfo->pszSubjPhone, pFields) ||
		!Add(pInfo->pszSubjEMail, pFields) ||
		!Add(pInfo->pszSubjDNS, pFields) ||
		!Add(pInfo->pszSubjEDRPOUCode, pFields) ||
		!Add(pInfo->pszSubjDRFOCode, pFields) ||
		!Add(pInfo->pszSubjNBUCode, pFields) ||
		!Add(pInfo->pszSubjSPFMCode, pFields) ||
		!Add(pInfo->pszSubjOCode, pFields) ||
		!Add(pInfo->pszSubjOUCode, pFields) ||
		!Add(pInfo->pszSubjUserCode, pFields) ||
		!Add(&pInfo->stCertBeginTime, pFields) ||
		!Add(&pInfo->stCertEndTime, pFields) ||
		!Add(pInfo->bPrivKeyTimes, pFields) ||
		!Add(&pInfo->stPrivKeyBeginTime, pFields) ||
		!Add(&pInfo->stPrivKeyEndTime, pFields) ||
		!Add(pInfo->dwPublicKeyBits, pFields) ||
		!Add(pInfo->pszPublicKey, pFields) ||
		!Add(pInfo->pszPublicKeyID, pFields) ||
		!Add(pInfo->pszIssuerPublicKeyID, pFields) ||
		!Add(pInfo->pszKeyUsage, pFields) ||
		!Add(pInfo->pszExtKeyUsages, pFields) ||
		!Add(pInfo->pszPolicies, pFields) ||
		!Add(pInfo->pszCRLDistribPoint1, pFields) ||
		!Add(pInfo->pszCRLDistribPoint2, pFields) ||
		!Add(pInfo->bPowerCert, pFields) ||
		!Add(pInfo->bSubjType, pFields) ||
		!Add(pInfo->bSubjCA, pFields) ||
		!Add(pInfo->iChainLength, pFields) ||
		!Add(pInfo->pszUPN, pFields) ||
		!Add(pInfo->dwPublicKeyType, pFields) ||
		!Add(pInfo->dwKeyUsage, pFields) ||
		!Add(pInfo->pszRSAModul, pFields) ||
		!Add(pInfo->pszRSAExponent, pFields) ||
		!Add(pInfo->pszOCSPAccessInfo, pFields) ||
		!Add(pInfo->pszIssuerAccessInfo, pFields) ||
		!Add(pInfo->pszTSPAccessInfo, pFields) ||
		!Add(pInfo->bLimitValueAvailable, pFields) ||
		!Add(pInfo->dwLimitValue, pFields) ||
		!Add(pInfo->pszLimitValueCurrency, pFields) ||
		!Add(pInfo->dwSubjType, pFields) ||
		!Add(pInfo->dwSubjSubType, pFields) ||
		!Add(pInfo->pszSubjUNZR, pFields) ||
		!Add(pInfo->pszSubjCountry, pFields) ||
		!Add(pInfo->pszFingerprint, pFields) ||
		!Add(pInfo->bQSCD, pFields) ||
		!Add(pInfo->pszSubjUserID, pFields) ||
		!Add(pInfo->dwCertHashType, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_CERT_OWNER_INFO	pInfo,
	PSTRUCT_FIELDS		pFields)
{
	if (!Alloc(CERT_OWNER_INFO_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->bFilled, pFields) ||
		!Add(pInfo->pszIssuer, pFields) ||
		!Add(pInfo->pszIssuerCN, pFields) ||
		!Add(pInfo->pszSerial, pFields) ||
		!Add(pInfo->pszSubject, pFields) ||
		!Add(pInfo->pszSubjCN, pFields) ||
		!Add(pInfo->pszSubjOrg, pFields) ||
		!Add(pInfo->pszSubjOrgUnit, pFields) ||
		!Add(pInfo->pszSubjTitle, pFields) ||
		!Add(pInfo->pszSubjState, pFields) ||
		!Add(pInfo->pszSubjLocality, pFields) ||
		!Add(pInfo->pszSubjFullName, pFields) ||
		!Add(pInfo->pszSubjAddress, pFields) ||
		!Add(pInfo->pszSubjPhone, pFields) ||
		!Add(pInfo->pszSubjEMail, pFields) ||
		!Add(pInfo->pszSubjDNS, pFields) ||
		!Add(pInfo->pszSubjEDRPOUCode, pFields) ||
		!Add(pInfo->pszSubjDRFOCode, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_USER_INFO			pUserInfo)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	memset(pUserInfo, 0, sizeof(EU_USER_INFO));

	if (!Get(pFields, &pUserInfo->dwVersion) ||
		!Get(pFields, pUserInfo->szCommonName,
			sizeof(pUserInfo->szCommonName)) ||
		!Get(pFields, pUserInfo->szLocality,
			 sizeof(pUserInfo->szLocality)) ||
		!Get(pFields, pUserInfo->szState,
			 sizeof(pUserInfo->szState)) ||
		!Get(pFields, pUserInfo->szOrganiztion,
			 sizeof(pUserInfo->szOrganiztion)) ||
		!Get(pFields, pUserInfo->szOrgUnit,
			 sizeof(pUserInfo->szOrgUnit)) ||
		!Get(pFields, pUserInfo->szTitle,
			 sizeof(pUserInfo->szTitle)) ||
		!Get(pFields, pUserInfo->szStreet,
			 sizeof(pUserInfo->szStreet)) ||
		!Get(pFields, pUserInfo->szPhone,
			 sizeof(pUserInfo->szPhone)) ||
		!Get(pFields, pUserInfo->szSurname,
			 sizeof(pUserInfo->szSurname)) ||
		!Get(pFields, pUserInfo->szGivenname,
			 sizeof(pUserInfo->szGivenname)) ||
		!Get(pFields, pUserInfo->szEMail,
			 sizeof(pUserInfo->szEMail)) ||
		!Get(pFields, pUserInfo->szDNS,
			 sizeof(pUserInfo->szDNS)) ||
		!Get(pFields, pUserInfo->szEDRPOUCode,
			 sizeof(pUserInfo->szEDRPOUCode)) ||
		!Get(pFields, pUserInfo->szDRFOCode,
			 sizeof(pUserInfo->szDRFOCode)) ||
		!Get(pFields, pUserInfo->szNBUCode,
			 sizeof(pUserInfo->szNBUCode)) ||
		!Get(pFields, pUserInfo->szSPFMCode,
			 sizeof(pUserInfo->szSPFMCode)) ||
		!Get(pFields, pUserInfo->szOCode,
			 sizeof(pUserInfo->szOCode)) ||
		!Get(pFields, pUserInfo->szOUCode,
			 sizeof(pUserInfo->szOUCode)) ||
		!Get(pFields, pUserInfo->szUserCode,
			 sizeof(pUserInfo->szUserCode)) ||
		!Get(pFields, pUserInfo->szUPN,
			 sizeof(pUserInfo->szUPN)) ||
		!Get(pFields, pUserInfo->szUNZR,
			 sizeof(pUserInfo->szUNZR)) ||
		!Get(pFields, pUserInfo->szCountry,
			 sizeof(pUserInfo->szCountry)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_REQUEST_INFO		pInfo,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(REQUEST_INFO_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pInfo->dwType, pFields) ||
		!Add(&pInfo->Request, pFields) ||
		!Add(pInfo->szFileName, pFields) ||
		!Add(pInfo->pInfo->bFilled, pFields) ||
		!Add(pInfo->pInfo->dwVersion, pFields) ||
		!Add(pInfo->pInfo->bSimple, pFields) ||
		!Add(pInfo->pInfo->pszSubject, pFields) ||
		!Add(pInfo->pInfo->pszSubjCN, pFields) ||
		!Add(pInfo->pInfo->pszSubjOrg, pFields) ||
		!Add(pInfo->pInfo->pszSubjOrgUnit, pFields) ||
		!Add(pInfo->pInfo->pszSubjTitle, pFields) ||
		!Add(pInfo->pInfo->pszSubjState, pFields) ||
		!Add(pInfo->pInfo->pszSubjLocality, pFields) ||
		!Add(pInfo->pInfo->pszSubjFullName, pFields) ||
		!Add(pInfo->pInfo->pszSubjAddress, pFields) ||
		!Add(pInfo->pInfo->pszSubjPhone, pFields) ||
		!Add(pInfo->pInfo->pszSubjEMail, pFields) ||
		!Add(pInfo->pInfo->pszSubjDNS, pFields) ||
		!Add(pInfo->pInfo->pszSubjEDRPOUCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjDRFOCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjNBUCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjSPFMCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjOCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjOUCode, pFields) ||
		!Add(pInfo->pInfo->pszSubjUserCode, pFields) ||
		!Add(pInfo->pInfo->bCertTimes, pFields) ||
		!Add(&pInfo->pInfo->stCertBeginTime, pFields) ||
		!Add(&pInfo->pInfo->stCertEndTime, pFields) ||
		!Add(pInfo->pInfo->bPrivKeyTimes, pFields) ||
		!Add(&pInfo->pInfo->stPrivKeyBeginTime, pFields) ||
		!Add(&pInfo->pInfo->stPrivKeyEndTime, pFields) ||
		!Add(pInfo->pInfo->dwPublicKeyType, pFields) ||
		!Add(pInfo->pInfo->dwPublicKeyBits, pFields) ||
		!Add(pInfo->pInfo->pszPublicKey, pFields) ||
		!Add(pInfo->pInfo->pszRSAModul, pFields) ||
		!Add(pInfo->pInfo->pszRSAExponent, pFields) ||
		!Add(pInfo->pInfo->pszPublicKeyID, pFields) ||
		!Add(pInfo->pInfo->pszExtKeyUsages, pFields) ||
		!Add(pInfo->pInfo->pszCRLDistribPoint1, pFields) ||
		!Add(pInfo->pInfo->pszCRLDistribPoint2, pFields) ||
		!Add(pInfo->pInfo->bSubjType, pFields) ||
		!Add(pInfo->pInfo->dwSubjType, pFields) ||
		!Add(pInfo->pInfo->dwSubjSubType, pFields) ||
		!Add(pInfo->pInfo->bSelfSigned, pFields) ||
		!Add(pInfo->pInfo->pszSignIssuer, pFields) ||
		!Add(pInfo->pInfo->pszSignSerial, pFields) ||
		!Add(pInfo->pInfo->pszSubjUNZR, pFields) ||
		!Add(pInfo->pInfo->pszSubjCountry, pFields) ||
		!Add(pInfo->pInfo->bQSCD, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_FILE_STORE_SETTINGS	pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(FILE_STORE_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->szPath, pFields) ||
		!Add(pSettings->bCheckCRLs, pFields) ||
		!Add(pSettings->bAutoRefresh, pFields) ||
		!Add(pSettings->bOwnCRLsOnly, pFields) ||
		!Add(pSettings->bFullAndDeltaCRLs, pFields) ||
		!Add(pSettings->bAutoDownloadCRLs, pFields) ||
		!Add(pSettings->bSaveLoadedCerts, pFields) ||
		!Add(pSettings->dwExpireTime, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_FILE_STORE_SETTINGS	pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, pSettings->szPath, sizeof(pSettings->szPath)) ||
		!Get(pFields, &pSettings->bCheckCRLs) ||
		!Get(pFields, &pSettings->bAutoRefresh) ||
		!Get(pFields, &pSettings->bOwnCRLsOnly) ||
		!Get(pFields, &pSettings->bFullAndDeltaCRLs) ||
		!Get(pFields, &pSettings->bAutoDownloadCRLs) ||
		!Get(pFields, &pSettings->bSaveLoadedCerts) ||
		!Get(pFields, &pSettings->dwExpireTime))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_PROXY_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(PROXY_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bUseProxy, pFields) ||
		!Add(pSettings->bAnonymus, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields) ||
		!Add(pSettings->szUser, pFields) ||
		!Add(pSettings->szPassword, pFields) ||
		!Add(pSettings->bSavePassword, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_PROXY_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bUseProxy) ||
		!Get(pFields, &pSettings->bAnonymus) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)) ||
		!Get(pFields, pSettings->szUser, sizeof(pSettings->szUser)) ||
		!Get(pFields, pSettings->szPassword, sizeof(pSettings->szPassword)) ||
		!Get(pFields, &pSettings->bSavePassword))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_OCSP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(OCSP_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bUseOCSP, pFields) ||
		!Add(pSettings->bBeforeStore, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_OCSP_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bUseOCSP) ||
		!Get(pFields, &pSettings->bBeforeStore) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_TSP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(TSP_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bGetStamps, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_TSP_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bGetStamps) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_LDAP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(LDAP_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bUseLDAP, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields) ||
		!Add(pSettings->bAnonymous, pFields) ||
		!Add(pSettings->szUser, pFields) ||
		!Add(pSettings->szPassword, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_LDAP_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bUseLDAP) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)) ||
		!Get(pFields, &pSettings->bAnonymous) ||
		!Get(pFields, pSettings->szUser, sizeof(pSettings->szUser)) ||
		!Get(pFields, pSettings->szPassword, sizeof(pSettings->szPassword)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_CMP_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(CMP_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bUseCMP, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields) ||
		!Add(pSettings->szCommonName, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_CMP_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bUseCMP) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)) ||
		!Get(pFields, pSettings->szCommonName, sizeof(pSettings->szCommonName)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_OCSP_ACCESS_INFO_MODE_SETTINGS	pSettings,
	PSTRUCT_FIELDS						pFields)
{
	if (!Alloc(OCSP_ACCESS_INFO_MODE_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bEnabled, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS						pFields,
	PEU_OCSP_ACCESS_INFO_MODE_SETTINGS	pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bEnabled))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_OCSP_ACCESS_INFO_SETTINGS	pSettings,
	PSTRUCT_FIELDS					pFields)
{
	if (!Alloc(OCSP_ACCESS_INFO_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->szIssuerCN, pFields) ||
		!Add(pSettings->szAddress, pFields) ||
		!Add(pSettings->szPort, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS					pFields,
	PEU_OCSP_ACCESS_INFO_SETTINGS	pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, pSettings->szIssuerCN, sizeof(pSettings->szIssuerCN)) ||
		!Get(pFields, pSettings->szAddress, sizeof(pSettings->szAddress)) ||
		!Get(pFields, pSettings->szPort, sizeof(pSettings->szPort)))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_LOG_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(LOG_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bSystem, pFields) ||
		!Add(pSettings->bUseReportAgent, pFields) ||
		!Add(pSettings->szReportAgentAddress, pFields) ||
		!Add(pSettings->szReportAgentPort, pFields) ||
		!Add(pSettings->bOnlyErrors, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_LOG_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bSystem) ||
		!Get(pFields, &pSettings->bUseReportAgent) ||
		!Get(pFields, pSettings->szReportAgentAddress, sizeof(pSettings->szReportAgentAddress)) ||
		!Get(pFields, pSettings->szReportAgentPort, sizeof(pSettings->szReportAgentPort)) ||
		!Get(pFields, &pSettings->bOnlyErrors))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Encode(
	PEU_MODE_SETTINGS		pSettings,
	PSTRUCT_FIELDS			pFields)
{
	if (!Alloc(MODE_SETTINGS_FIELDS_COUNT, pFields))
		return FALSE;

	if (!Add(pSettings->bOffline, pFields))
	{
		Free(pFields);

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_MODE_SETTINGS		pSettings)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pSettings->bOffline))
	{
		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------------------

int Decode(
	PSTRUCT_FIELDS			pFields,
	PEU_KEY_MEDIA			pKeyMedia)
{
	if (!pFields)
		return FALSE;

	pFields->nIndex = 0;

	if (!Get(pFields, &pKeyMedia->dwTypeIndex) ||
		!Get(pFields, &pKeyMedia->dwDevIndex) ||
		!Get(pFields, pKeyMedia->szPassword, sizeof(pKeyMedia->szPassword)))
	{
		return FALSE;
	}

	return TRUE;
}

//==============================================================================
