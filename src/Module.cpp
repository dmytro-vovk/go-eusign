//================================================================================

#include "Module.h"

#include "StringCoder.h"
#include "StructFieldsCoder.h"

#include "EUError.h"
#include "EUSignCP.h"

#include <stdio.h>

//================================================================================

#define EU_ERROR_MESSAGE_MAX_LENGTH							1025

const char*	EU_ERROR_NOT_INITIALIZED_UA_STRING				=
	"Бібліотека не ініціалізована";
const char*	EU_ERROR_NOT_INITIALIZED_RU_STRING				=
	"Библиотека не инициализирована";
const char*	EU_ERROR_NOT_INITIALIZED_EN_STRING				=
	"Library is not initialized";

//================================================================================

static PEU_INTERFACE	s_pIface = NULL;

static int				s_bForbidChdir = 0;
static char				s_szSettingsPath[EU_PATH_MAX_LENGTH] = {0, };
static unsigned long	s_dwRegRootKey = EU_REG_KEY_ROOT_PATH_DEFAULT;
static char				s_szRegPath[EU_PATH_MAX_LENGTH] = {0, };

//================================================================================

unsigned long FreeMemory(
	unsigned char*	pbMemory)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->FreeMemory(pbMemory);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long FreeCertificatesArray(
	unsigned long	dwCertificatesCount,
	unsigned char	**ppbCertificates,
	unsigned long	*pdwCertificatesLengthes)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->FreeCertificatesArray(dwCertificatesCount, 
		ppbCertificates, pdwCertificatesLengthes);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxFreeMemory(
	void*			pvPrivateKeyContext,
	unsigned char*	pbMemory)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->CtxFreeMemory(pvPrivateKeyContext, pbMemory);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long FreeCStrings(
	char*			*ppszStrings,
	unsigned long	dwCount)
{
	FreeStringArray(dwCount, ppszStrings);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long FreeStructFields(
	char*			*ppszFields,
	unsigned long	dwFields)
{
	STRUCT_FIELDS	Fields;

	Fields.nCount = dwFields;
	Fields.nIndex = dwFields;
	Fields.ppszFields = ppszFields;

	Free(&Fields);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AllocStructFields(
	unsigned long	dwFields,
	char*			**pppszFields)
{
	STRUCT_FIELDS	Fields;

	if (!Alloc(dwFields, &Fields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszFields = Fields.ppszFields;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetErrorLangDesc(
	unsigned long	dwError,
	unsigned long	dwLang,
	char*			szMessage)
{
	const char*		pszMessage;

	if (s_pIface == NULL)
	{
		switch (dwLang)
		{
			case EU_RU_LANG:
				pszMessage = EU_ERROR_NOT_INITIALIZED_RU_STRING;
				break;

			case EU_EN_LANG:
				pszMessage = EU_ERROR_NOT_INITIALIZED_EN_STRING;
				break;

			case EU_UA_LANG:
			default:
				pszMessage = EU_ERROR_NOT_INITIALIZED_UA_STRING;
				break;
		}
	}
	else
	{
		pszMessage = s_pIface->GetErrorLangDesc(dwError, dwLang);
	}
	
	if (!ConvertString(
			CP_ACP, pszMessage,
			CP_UTF8, szMessage, 
			EU_ERROR_MESSAGE_MAX_LENGTH))
	{
		strcpy(szMessage, "");
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long BASE64Encode(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	char*			*ppszData)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->BASE64Encode(
		pbData, dwDataLength, ppszData);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long Initialize()
{
	int				bUTC = 1;
	unsigned long	dwError;

	if (s_pIface != NULL)
		return EU_ERROR_NONE;

	if (!EULoad())
		return EU_ERROR_LIBRARY_LOAD;

	s_pIface = EUGetInterface();
	if (s_pIface == NULL)
	{
		EUUnload();

		return EU_ERROR_LIBRARY_LOAD;
	}

	s_pIface->SetUIMode(FALSE);

	dwError = s_pIface->SetRuntimeParameter(
		(char *) EU_FORBID_CHDIR_PARAMETER, &s_bForbidChdir,
		EU_FORBID_CHDIR_LENGTH);
	if (dwError != EU_ERROR_NONE)
	{
		s_pIface = NULL;
		EUUnload();

		return dwError;
	}

	dwError = s_pIface->SetSettingsFilePathEx(
		s_szSettingsPath, s_dwRegRootKey, s_szRegPath);
	if (dwError != EU_ERROR_NONE)
	{
		s_pIface = NULL;
		EUUnload();

		return dwError;
	}

	dwError = s_pIface->Initialize();
	if (dwError != EU_ERROR_NONE)
	{
		s_pIface = NULL;
		EUUnload();

		return dwError;
	}

	s_pIface->SetUIMode(FALSE);

	dwError = s_pIface->SetRuntimeParameter(
		(char *) EU_USE_UTC_TIME_PARAMETER, &bUTC, 
		EU_USE_UTC_TIME_PARAMETER_LENGTH);
	if (dwError != EU_ERROR_NONE)
	{
		s_pIface->Finalize();
		s_pIface = NULL;
		EUUnload();

		return dwError;
	}

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long Finalize()
{
	if (s_pIface != NULL)
	{
		s_pIface->Finalize();
		s_pIface = NULL;
	}

	EUUnload();

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

int IsInitialized()
{
	int				bIsInitialized;

	if (s_pIface == NULL)
		return FALSE;

	bIsInitialized = s_pIface->IsInitialized();

	return bIsInitialized;
}

//--------------------------------------------------------------------------------

unsigned long DoesNeedSetSettings(
	int*			pbDoesNeedSetSettings)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	*pbDoesNeedSetSettings = s_pIface->DoesNeedSetSettings();

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetSettingsFilePathEx(
	char*			pszSettingsPath,
	unsigned long	dwRootKey,
	char*			pszRegPath)
{
	unsigned long	dwError;

	if (!ConvertString(
			CP_UTF8, pszSettingsPath,
			CP_ACP, s_szSettingsPath,
			sizeof(s_szSettingsPath)) ||
		!ConvertString(
			CP_UTF8, pszRegPath,
			CP_ACP, s_szRegPath,
			sizeof(s_szRegPath)))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_dwRegRootKey = dwRootKey;

	if (s_pIface != NULL)
	{
		dwError = s_pIface->SetSettingsFilePathEx(
			s_szSettingsPath, dwRootKey, s_szRegPath);
		if (dwError != EU_ERROR_NONE)
			return dwError;
	}

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetModeSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_MODE_SETTINGS		Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetModeSettings(
		&Settings.bOffline);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetModeSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_MODE_SETTINGS		Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetModeSettings(
		Settings.bOffline);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetFileStoreSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_FILE_STORE_SETTINGS	Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetFileStoreSettings(
		Settings.szPath,
		&Settings.bCheckCRLs,
		&Settings.bAutoRefresh,
		&Settings.bOwnCRLsOnly,
		&Settings.bFullAndDeltaCRLs,
		&Settings.bAutoDownloadCRLs,
		&Settings.bSaveLoadedCerts,
		&Settings.dwExpireTime);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetFileStoreSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_FILE_STORE_SETTINGS	Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetFileStoreSettings(
		Settings.szPath,
		Settings.bCheckCRLs,
		Settings.bAutoRefresh,
		Settings.bOwnCRLsOnly,
		Settings.bFullAndDeltaCRLs,
		Settings.bAutoDownloadCRLs,
		Settings.bSaveLoadedCerts,
		Settings.dwExpireTime);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetProxySettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_PROXY_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetProxySettings(
		&Settings.bUseProxy,
		&Settings.bAnonymus,
		Settings.szAddress,
		Settings.szPort,
		Settings.szUser,
		Settings.szPassword,
		&Settings.bSavePassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetProxySettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_PROXY_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetProxySettings(
		Settings.bUseProxy,
		Settings.bAnonymus,
		Settings.szAddress,
		Settings.szPort,
		Settings.szUser,
		Settings.szPassword,
		Settings.bSavePassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetOCSPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_OCSP_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetOCSPSettings(
		&Settings.bUseOCSP,
		&Settings.bBeforeStore,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetOCSPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_OCSP_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetOCSPSettings(
		Settings.bUseOCSP,
		Settings.bBeforeStore,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetOCSPAccessInfoModeSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_OCSP_ACCESS_INFO_MODE_SETTINGS	Settings;
	STRUCT_FIELDS						InfoFields;
	unsigned long						dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetOCSPAccessInfoModeSettings(
		&Settings.bEnabled);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetOCSPAccessInfoModeSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_OCSP_ACCESS_INFO_MODE_SETTINGS	Settings;
	STRUCT_FIELDS						InfoFields;
	unsigned long						dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetOCSPAccessInfoModeSettings(
		Settings.bEnabled);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long EnumOCSPAccessInfoSettings(
	unsigned long	dwIndex,
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_OCSP_ACCESS_INFO_SETTINGS	Settings;
	STRUCT_FIELDS					InfoFields;
	unsigned long					dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->EnumOCSPAccessInfoSettings(
		dwIndex,
		Settings.szIssuerCN,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetOCSPAccessInfoSettings(
	char*			pszIssuerCN,
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_OCSP_ACCESS_INFO_SETTINGS	Settings;
	STRUCT_FIELDS					InfoFields;
	unsigned long					dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszIssuerCN,
			CP_ACP, Settings.szIssuerCN, 
			EU_ISSUER_MAX_LENGTH))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GetOCSPAccessInfoSettings(
		Settings.szIssuerCN,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetOCSPAccessInfoSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_OCSP_ACCESS_INFO_SETTINGS	Settings;
	STRUCT_FIELDS					InfoFields;
	unsigned long					dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetOCSPAccessInfoSettings(
		Settings.szIssuerCN,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long DeleteOCSPAccessInfoSettings(
	char*			pszIssuerCN)
{
	char			szIssuerCN[EU_ISSUER_MAX_LENGTH];
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszIssuerCN,
			CP_ACP, szIssuerCN, 
			EU_ISSUER_MAX_LENGTH))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->DeleteOCSPAccessInfoSettings(
		szIssuerCN);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetTSPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_TSP_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetTSPSettings(
		&Settings.bGetStamps,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetTSPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_TSP_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetTSPSettings(
		Settings.bGetStamps,
		Settings.szAddress,
		Settings.szPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetLDAPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_LDAP_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetLDAPSettings(
		&Settings.bUseLDAP,
		Settings.szAddress,
		Settings.szPort,
		&Settings.bAnonymous,
		Settings.szUser,
		Settings.szPassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetLDAPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_LDAP_SETTINGS	Settings;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetLDAPSettings(
		Settings.bUseLDAP,
		Settings.szAddress,
		Settings.szPort,
		Settings.bAnonymous,
		Settings.szUser,
		Settings.szPassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetCMPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_CMP_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetCMPSettings(
		&Settings.bUseCMP,
		Settings.szAddress,
		Settings.szPort,
		Settings.szCommonName);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetCMPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_CMP_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetCMPSettings(
		Settings.bUseCMP,
		Settings.szAddress,
		Settings.szPort,
		Settings.szCommonName);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetLogSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_LOG_SETTINGS			Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetLogSettings(
		&Settings.bSystem,
		&Settings.bUseReportAgent,
		Settings.szReportAgentAddress,
		Settings.szReportAgentPort,
		&Settings.bOnlyErrors);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetLogSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_LOG_SETTINGS			Settings;
	STRUCT_FIELDS			InfoFields;
	unsigned long			dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetLogSettings(
		Settings.bSystem,
		Settings.bUseReportAgent,
		Settings.szReportAgentAddress,
		Settings.szReportAgentPort,
		Settings.bOnlyErrors);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetTSLSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings)
{
	EU_TSL_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetTSLSettings(
		&Settings.bUseTSL,
		&Settings.bAutoDownloadTSL,
		Settings.szTSLAddress);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Settings, &InfoFields))
		return EU_ERROR_MEMORY_ALLOCATION;

	*pppszSettings = InfoFields.ppszFields;
	*pdwSettings    = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetTSLSettings(
	char			**ppszSettings,
	unsigned long	dwSettings)
{
	EU_TSL_SETTINGS	Settings;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszSettings;
	InfoFields.nCount = dwSettings;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &Settings))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->SetTSLSettings(
		Settings.bUseTSL,
		Settings.bAutoDownloadTSL,
		Settings.szTSLAddress);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SetRuntimeParameter(
	char*			pszParameterName,
	void*			pvParameterValue,
	unsigned long	dwParameterValueLength)
{
	int				bParameterValueSet = 0;
	unsigned long	dwError;

	if ((dwParameterValueLength == 
			EU_FORBID_CHDIR_LENGTH) && 
		!strcmp(pszParameterName,
			EU_FORBID_CHDIR_PARAMETER))
	{
		s_bForbidChdir = *((int *) pvParameterValue);
		bParameterValueSet = 1;
	}

	if (s_pIface == NULL)
	{
		return bParameterValueSet ? 
			EU_ERROR_NONE : EU_ERROR_NOT_INITIALIZED;
	}

	dwError = s_pIface->SetRuntimeParameter(
		pszParameterName, pvParameterValue,
		dwParameterValueLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return dwError;
}

//--------------------------------------------------------------------------------

unsigned long SetOCSPResponseExpireTime(
	unsigned long	dwExpireTime)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SetOCSPResponseExpireTime(dwExpireTime);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SaveCertificate(
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SaveCertificate(
		pbCertificate,
		dwCertificateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long DeleteCertificate(
	char*			pszIssuer,
	char*			pszSerial)
{
	unsigned long	dwError;
	char			szIssuer[EU_ISSUER_MAX_LENGTH];
	char			szSerial[EU_SERIAL_MAX_LENGTH];

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszIssuer,
			CP_ACP, szIssuer,
			EU_ISSUER_MAX_LENGTH) ||
		!ConvertString(
			CP_UTF8, pszSerial,
			CP_ACP, szSerial,
			EU_SERIAL_MAX_LENGTH))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->DeleteCertificate(
		szIssuer, szSerial);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SaveCertificates(
	unsigned char*	pbCertificates,
	unsigned long	dwCertificatesLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SaveCertificates(
		pbCertificates,
		dwCertificatesLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SaveCertificatesEx(
	unsigned char*	pbCertificates,
	unsigned long	dwCertificatesLength,
	unsigned char*	pbTrustedCertificates,
	unsigned long	dwTrustedCertificatesLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SaveCertificatesEx(
		pbCertificates,
		dwCertificatesLength,
		pbTrustedCertificates,
		dwTrustedCertificatesLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SaveTSL(
	unsigned char*	pbTSL,
	unsigned long	dwTSLLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SaveTSL(
		pbTSL, dwTSLLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long EnumCertificatesEx(
	unsigned long	dwSubjectType,
	unsigned long	dwSubjectSubType,
	unsigned long	dwCertKeyType,
	unsigned long	dwKeyUsage,
	unsigned long	dwIndex,
	char*			**pppszInfo,
	unsigned long	*pdwInfo,
	unsigned char*	*ppbCertificate,
	unsigned long*	pdwCertificateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->EnumCertificatesEx(
		dwSubjectType, dwSubjectSubType, dwCertKeyType,
		dwKeyUsage, dwIndex, &pInfo, ppbCertificate,
		pdwCertificateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetCertificate(
	char*			pszIssuer,
	char*			pszSerial,
	unsigned char*	*ppbCertificate,
	unsigned long*	pdwCertificateLength)
{
	unsigned long	dwError;
	char			szIssuer[EU_ISSUER_MAX_LENGTH];
	char			szSerial[EU_SERIAL_MAX_LENGTH];

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszIssuer,
			CP_ACP, szIssuer,
			EU_ISSUER_MAX_LENGTH) ||
		!ConvertString(
			CP_UTF8, pszSerial,
			CP_ACP, szSerial,
			EU_SERIAL_MAX_LENGTH))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GetCertificate(
		szIssuer, szSerial, NULL,
		ppbCertificate, pdwCertificateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ParseCertificateEx(
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength,
	char*			**pppszInfo,
	unsigned long	*pdwInfo)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ParseCertificateEx(
		pbCertificate, dwCertificateLength, &pInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetCertificatesByKeyInfo(
	unsigned char*	pbPrivKeyInfo,
	unsigned long	dwPrivKeyInfoLength,
	char*			*ppszCMPServers,
	unsigned long	dwCMPServersCount,
	char*			*ppszCMPServersPorts,
	unsigned long	dwCMPServersPortsCount,
	unsigned char*	*pbCertificates,
	unsigned long*	pdwCertificates)
{
	char*			pszCMPServers;
	char*			pszCMPServersPorts;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!StringArrayToString(
			(const char**) ppszCMPServers, dwCMPServersCount,
			&pszCMPServers))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	if (!StringArrayToString(
			(const char**) ppszCMPServersPorts, dwCMPServersPortsCount,
			&pszCMPServersPorts))
	{
		delete[] pszCMPServers;
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GetCertificatesByKeyInfo(
		pbPrivKeyInfo, dwPrivKeyInfoLength,
		pszCMPServers, pszCMPServersPorts, 
		pbCertificates, pdwCertificates);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszCMPServers;
		delete[] pszCMPServersPorts;

		return dwError;
	}

	delete[] pszCMPServers;
	delete[] pszCMPServersPorts;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long EnumKeyMediaTypes(
	unsigned long	dwTypeIndex,
	char*			*ppszTypeDescription)
{
	char			szTypeDescription[EU_KEY_MEDIA_NAME_MAX_LENGTH];
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->EnumKeyMediaTypes(
		dwTypeIndex, 
		szTypeDescription);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!ConvertString(
			CP_ACP, szTypeDescription,
			CP_UTF8, ppszTypeDescription))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long EnumKeyMediaDevices(
	unsigned long	dwTypeIndex,
	unsigned long	dwDeviceIndex,
	char*			*ppszDeviceDescription)
{
	char			szDeviceDescription[EU_KEY_MEDIA_NAME_MAX_LENGTH];
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->EnumKeyMediaDevices(
		dwTypeIndex,
		dwDeviceIndex,
		szDeviceDescription);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!ConvertString(
			CP_ACP, szDeviceDescription,
			CP_UTF8, ppszDeviceDescription))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GeneratePrivateKey2(
	char			**ppszKeyMedia,
	unsigned long	dwKeyMedia,
	int				bSetKeyMediaPassword,
	unsigned long	dwUAKeysType,
	unsigned long	dwUADSKeysSpec,
	unsigned long	dwUAKEPKeysSpec,
	char*			pszUAParamsPath,
	unsigned long	dwIntKeysType,
	unsigned long	dwRSAKeysSpec,
	char*			pszRSAParamsPath,
	unsigned long	dwECDSAKeysSpec,
	char*			pszECDSAParamsPath,
	char			**ppszUserInfo,
	unsigned long	dwUserInfo,
	char*			pszExtKeyUsages,
	char*			**pppszUARequest,
	unsigned long	*pdwUARequest,
	char*			**pppszUAKEPRequest,
	unsigned long	*pdwUAKEPRequest,
	char*			**pppszRSARequest,
	unsigned long	*pdwRSARequest,
	char*			**pppszECDSARequest,
	unsigned long	*pdwECDSARequest)
{
	EU_KEY_MEDIA	KeyMedia;
	EU_USER_INFO	UserInfo;
	EU_REQUEST_INFO	UADSRequest = {EU_REQUEST_TYPE_UA_DS, };
	EU_REQUEST_INFO	UAKEPRequest = {EU_REQUEST_TYPE_UA_KEP, };
	EU_REQUEST_INFO	RSARequest = {EU_REQUEST_TYPE_RSA, };
	EU_REQUEST_INFO	ECDSARequest = {EU_REQUEST_TYPE_ECDSA, };
	PEU_REQUEST_INFO	Requests[] = {
		&UADSRequest, &UAKEPRequest, 
		&RSARequest, &ECDSARequest
	};
	STRUCT_FIELDS	InfoFields;
	STRUCT_FIELDS	UADSRequestFields = {NULL, };
	STRUCT_FIELDS	UAKEPRequestFields = {NULL, };
	STRUCT_FIELDS	RSARequestFields = {NULL, };
	STRUCT_FIELDS	ECDSARequestFields = {NULL, };
	PSTRUCT_FIELDS	RequestsFields[] = {
		&UADSRequestFields, &UAKEPRequestFields,
		&RSARequestFields, &ECDSARequestFields
	};
	char			szUAParamsPath[EU_PATH_MAX_LENGTH];
	char			szRSAParamsPath[EU_PATH_MAX_LENGTH];
	char			szECDSAParamsPath[EU_PATH_MAX_LENGTH];
	char*			pszACPExtKeyUsages = NULL;
	int				bGenUAKey = (dwUAKeysType ==
			EU_KEYS_TYPE_DSTU_AND_ECDH_WITH_GOSTS) ||
		(dwUAKeysType == 
			EU_KEYS_TYPE_DSTU_AND_ECDH_WITH_DSTU);
	int				bGenRSAKey = ((dwIntKeysType &
		EU_KEYS_TYPE_RSA_WITH_SHA) != 0);
	int				bGenECDSAKey = ((dwIntKeysType &
		EU_KEYS_TYPE_ECDSA_WITH_SHA) != 0);
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszKeyMedia;
	InfoFields.nCount = dwKeyMedia;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &KeyMedia))
		return EU_ERROR_MEMORY_ALLOCATION;

	if (ppszUserInfo != NULL)
	{
		InfoFields.ppszFields = ppszUserInfo;
		InfoFields.nCount = dwUserInfo;
		InfoFields.nIndex = 0;

		if (!Decode(&InfoFields, &UserInfo))
			return EU_ERROR_MEMORY_ALLOCATION;
	}

	if (!ConvertString(
			CP_UTF8, pszUAParamsPath,
			CP_ACP, szUAParamsPath,
			EU_PATH_MAX_LENGTH) ||
		!ConvertString(
			CP_UTF8, pszRSAParamsPath,
			CP_ACP, szRSAParamsPath,
			EU_PATH_MAX_LENGTH) ||
		!ConvertString(
			CP_UTF8, pszECDSAParamsPath,
			CP_ACP, szECDSAParamsPath,
			EU_PATH_MAX_LENGTH) ||
		(pszExtKeyUsages != NULL &&
		!ConvertString(
			CP_UTF8, pszExtKeyUsages,
			CP_ACP, &pszACPExtKeyUsages)))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GeneratePrivateKey2(
		&KeyMedia, bSetKeyMediaPassword,
		dwUAKeysType, dwUADSKeysSpec, dwUAKEPKeysSpec,
		szUAParamsPath, dwIntKeysType, dwRSAKeysSpec,
		szRSAParamsPath, dwECDSAKeysSpec, szECDSAParamsPath,
		ppszUserInfo ? &UserInfo : NULL, 
		pszACPExtKeyUsages, NULL, NULL, NULL, NULL,
		bGenUAKey ? &UADSRequest.Request.pbData : NULL,
		bGenUAKey ? &UADSRequest.Request.dwDataLength : 0,
		bGenUAKey ? UADSRequest.szFileName : NULL,
		bGenUAKey ? &UAKEPRequest.Request.pbData : NULL,
		bGenUAKey ? &UAKEPRequest.Request.dwDataLength : 0,
		bGenUAKey ? UAKEPRequest.szFileName : NULL,
		bGenRSAKey ? &RSARequest.Request.pbData : NULL,
		bGenRSAKey ? &RSARequest.Request.dwDataLength : 0,
		bGenRSAKey ? RSARequest.szFileName : NULL,
		bGenECDSAKey ? &ECDSARequest.Request.pbData : NULL,
		bGenECDSAKey ? &ECDSARequest.Request.dwDataLength : 0,
		bGenECDSAKey ? ECDSARequest.szFileName : NULL);
	if (dwError != EU_ERROR_NONE)
	{
		if (pszACPExtKeyUsages)
			delete[] pszACPExtKeyUsages;
		return dwError;
	}

	if (pszACPExtKeyUsages)
		delete[] pszACPExtKeyUsages;

	for (unsigned long dwI = 0; dwI < 
			sizeof(Requests) / sizeof(PEU_REQUEST_INFO); dwI++)
	{
		if (Requests[dwI]->Request.pbData == NULL)
			continue;

		dwError = s_pIface->GetCRInfo(
			Requests[dwI]->Request.pbData, 
			Requests[dwI]->Request.dwDataLength, 
			&Requests[dwI]->pInfo);
		if (dwError != EU_ERROR_NONE)
		{
			for (unsigned long dwJ = 0; dwJ < 
					sizeof(Requests) / sizeof(PEU_REQUEST_INFO); dwJ++)
			{
				if (Requests[dwJ]->Request.pbData == NULL)
					continue;

				s_pIface->FreeMemory(Requests[dwJ]->Request.pbData);
				if (Requests[dwJ]->pInfo)
					s_pIface->FreeCRInfo(Requests[dwJ]->pInfo);
				if (RequestsFields[dwJ]->ppszFields != NULL)
				{
					FreeStructFields(RequestsFields[dwJ]->ppszFields,
						RequestsFields[dwJ]->nCount);
				}
			}

			return dwError;
		}

		if (!Encode(Requests[dwI], RequestsFields[dwI]))
		{
			for (unsigned long dwJ = 0; dwJ < 
					sizeof(Requests) / sizeof(PEU_REQUEST_INFO); dwJ++)
			{
				if (Requests[dwJ]->Request.pbData == NULL)
					continue;

				s_pIface->FreeMemory(Requests[dwJ]->Request.pbData);
				if (Requests[dwJ]->pInfo)
					s_pIface->FreeCRInfo(Requests[dwJ]->pInfo);
				if (RequestsFields[dwJ]->ppszFields != NULL)
				{
					FreeStructFields(RequestsFields[dwJ]->ppszFields,
						RequestsFields[dwJ]->nCount);
				}
			}

			return EU_ERROR_MEMORY_ALLOCATION;
		}

		s_pIface->FreeMemory(Requests[dwI]->Request.pbData);
		s_pIface->FreeCRInfo(Requests[dwI]->pInfo);
		memset(Requests[dwI], 0, sizeof(EU_REQUEST_INFO));
	}

	*pppszUARequest = UADSRequestFields.ppszFields;
	*pdwUARequest = UADSRequestFields.nCount;
	*pppszUAKEPRequest = UAKEPRequestFields.ppszFields;
	*pdwUAKEPRequest = UAKEPRequestFields.nCount;
	*pppszRSARequest = RSARequestFields.ppszFields;
	*pdwRSARequest = RSARequestFields.nCount;
	*pppszECDSARequest = ECDSARequestFields.ppszFields;
	*pdwECDSARequest = ECDSARequestFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long IsPrivateKeyReaded(
	int				*pbIsPrivateKeyReaded)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	*pbIsPrivateKeyReaded = s_pIface->IsPrivateKeyReaded();

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ReadPrivateKey(
	char			**ppszKeyMedia,
	unsigned long	dwKeyMedia,
	char*			**pppszInfo,
	unsigned long	*pdwInfo)
{
	EU_KEY_MEDIA		KeyMedia;
	EU_CERT_OWNER_INFO	Info;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszKeyMedia;
	InfoFields.nCount = dwKeyMedia;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &KeyMedia))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->ReadPrivateKey(
		&KeyMedia, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeCertOwnerInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertOwnerInfo(&Info);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ResetPrivateKey()
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->ResetPrivateKey();

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxReadPrivateKey(
	void*				pvContext,
	char				**ppszKeyMedia,
	unsigned long		pdwKeyMedia,
	void*				*ppvPrivateKeyContext,
	char*				**pppszCertOwnerInfo,
	unsigned long		*pdwCertOwnerInfo)
{
	EU_KEY_MEDIA		KeyMedia;
	EU_CERT_OWNER_INFO	CertOwnerInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszKeyMedia;
	InfoFields.nCount = pdwKeyMedia;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &KeyMedia))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->CtxReadPrivateKey(
		pvContext, &KeyMedia,
		ppvPrivateKeyContext, &CertOwnerInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&CertOwnerInfo, &InfoFields))
	{
		s_pIface->CtxFreeCertOwnerInfo(
			*ppvPrivateKeyContext, &CertOwnerInfo);
		s_pIface->CtxFreePrivateKey(
			*ppvPrivateKeyContext);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertOwnerInfo(
		*ppvPrivateKeyContext, &CertOwnerInfo);

	*pppszCertOwnerInfo = InfoFields.ppszFields;
	*pdwCertOwnerInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxReadPrivateKeyBinary(
	void				*pvContext,
	unsigned char*		pbPrivateKey,
	unsigned long		dwPrivateKeyLength,
	char				*pszPassword,
	void*				*ppvPrivateKeyContext,
	char*				**pppszCertOwnerInfo,
	unsigned long		*pdwCertOwnerInfo)
{
	char				szPassword[EU_PASS_MAX_LENGTH];
	EU_CERT_OWNER_INFO	CertOwnerInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszPassword,
			CP_ACP, szPassword, 
			sizeof(szPassword)))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->CtxReadPrivateKeyBinary(
		pvContext, pbPrivateKey, dwPrivateKeyLength,
		szPassword, ppvPrivateKeyContext, &CertOwnerInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&CertOwnerInfo, &InfoFields))
	{
		s_pIface->CtxFreeCertOwnerInfo(
			*ppvPrivateKeyContext, &CertOwnerInfo);
		s_pIface->CtxFreePrivateKey(
			*ppvPrivateKeyContext);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertOwnerInfo(
		*ppvPrivateKeyContext, &CertOwnerInfo);

	*pppszCertOwnerInfo = InfoFields.ppszFields;
	*pdwCertOwnerInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxFreePrivateKey(
	void*			pvPrivateKeyContext)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->CtxFreePrivateKey(pvPrivateKeyContext);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxGetOwnCertificate(
	void*				pvPrivateKeyContext,
	unsigned long		dwCertKeyType,
	unsigned long		dwKeyUsage,
	char*				**pppszCertInfo,
	unsigned long		*pdwCertInfo,
	unsigned char*		*ppbCertificate,
	unsigned long*		pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxGetOwnCertificate(
		pvPrivateKeyContext, dwCertKeyType, dwKeyUsage,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->CtxFreeMemory(
			pvPrivateKeyContext, *ppbCertificate);
		s_pIface->CtxFreeCertificateInfoEx(
			pvPrivateKeyContext, pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertificateInfoEx(
			pvPrivateKeyContext, pInfo);

	*pppszCertInfo = InfoFields.ppszFields;
	*pdwCertInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetKeyInfo(
	char			**ppszKeyMedia,
	unsigned long	dwKeyMedia,
	unsigned char*	*ppbKeyInfo,
	unsigned long*	pdwKeyInfoLength)
{
	EU_KEY_MEDIA		KeyMedia;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	InfoFields.ppszFields = ppszKeyMedia;
	InfoFields.nCount = dwKeyMedia;
	InfoFields.nIndex = 0;

	if (!Decode(&InfoFields, &KeyMedia))
		return EU_ERROR_MEMORY_ALLOCATION;

	dwError = s_pIface->GetKeyInfo(
		&KeyMedia, ppbKeyInfo, pdwKeyInfoLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetKeyInfoBinary(
	unsigned char*	pbPrivateKey,
	unsigned long	dwPrivateKeyLength,
	char			*pszPassword,
	unsigned char*	*ppbKeyInfo,
	unsigned long*	pdwKeyInfoLength)
{
	char			szPassword[EU_PASS_MAX_LENGTH];
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszPassword,
			CP_ACP, szPassword, 
			sizeof(szPassword)))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GetKeyInfoBinary(
		pbPrivateKey, dwPrivateKeyLength,
		szPassword, ppbKeyInfo, pdwKeyInfoLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long EnumJKSPrivateKeys(
	unsigned char*	pbContainer,
	unsigned long	dwContainerLength,
	unsigned long	dwIndex,
	char*			*ppszKeyAlias)
{
	char*			pszKeyAlias;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->EnumJKSPrivateKeys(
		pbContainer,
		dwContainerLength,
		dwIndex,
		&pszKeyAlias);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!ConvertString(
			CP_ACP, pszKeyAlias,
			CP_UTF8, ppszKeyAlias))
	{
		s_pIface->FreeMemory((unsigned char*) pszKeyAlias);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeMemory((unsigned char*) pszKeyAlias);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetJKSPrivateKey(
	unsigned char*	pbContainer,
	unsigned long	dwContainerLength,
	char*			pszKeyAlias,
	unsigned char*	*ppbPrivateKey,
	unsigned long*	pdwPrivateKeyLength,
	unsigned long*	pdwCertificatesCount,
	unsigned char*	**ppbCertificates,
	unsigned long*	*ppdwCertificatesLengthes)
{
	char*			pszACPKeyAlias;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!ConvertString(
			CP_UTF8, pszKeyAlias,
			CP_ACP, &pszACPKeyAlias))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->GetJKSPrivateKey(
		pbContainer,
		dwContainerLength,
		pszACPKeyAlias,
		ppbPrivateKey,
		pdwPrivateKeyLength,
		pdwCertificatesCount,
		ppbCertificates,
		ppdwCertificatesLengthes);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszACPKeyAlias;
		return dwError;
	}

	delete[] pszACPKeyAlias;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxHashData(
	void*			pvContext,
	unsigned long	dwHashAlgo,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbHash,
	unsigned long	*pdwHashLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxHashData(
		pvContext, dwHashAlgo,
		NULL, 0, pbData, dwDataLength,
		ppbHash, pdwHashLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetSignType(
	unsigned long	dwSignIndex,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned long*	pdwSignType)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetSignType(
		dwSignIndex, NULL, pbSign, dwSignLength, pdwSignType);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetSignsCount(
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned long	*pdwCount)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetSignsCount(
		pszSign, pbSign, dwSignLength, pdwCount);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetSigner(
	unsigned long	dwSignIndex,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetSigner(dwSignIndex,
		NULL, pbSign, dwSignLength, NULL, ppbSigner, pdwSignerLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetSignerInfo(
	unsigned long		dwSignIndex,
	char*				pszSign,
	unsigned char*		pbSign,
	unsigned long		dwSignLength,
	char*				**pppszCertInfo,
	unsigned long		*pdwCertInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetSignerInfo(
		dwSignIndex, pszSign, pbSign, 
		dwSignLength, &pInfo, ppbCertificate,
		pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszCertInfo = InfoFields.ppszFields;
	*pdwCertInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long VerifyDataSpecific(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->VerifyDataSpecific(
		pbData, dwDataLength, dwSignIndex,
		pszSign, pbSign, dwSignLength, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long VerifyDataInternalSpecific(
	unsigned long	dwSignIndex,
	char*			pszSignedData,
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->VerifyDataInternalSpecific(
		dwSignIndex, pszSignedData, pbSignedData,
		dwSignedDataLength, ppbData, pdwDataLength, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbData);
		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long VerifyHashSpecific(
	char*			pszHash,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->VerifyHashSpecific(
		pszHash, pbHash, dwHashLength, dwSignIndex,
		pszSign, pbSign, dwSignLength, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CreateEmptySign(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbSign,
	unsigned long*	pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CreateEmptySign(
		pbData, dwDataLength, NULL,
		ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AppendValidationDataToSignerEx(
	unsigned char*	pbPreviousSigner,
	unsigned long	dwPreviousSignerLength,
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength,
	unsigned long	dwSignType,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AppendValidationDataToSignerEx(
		NULL, pbPreviousSigner, dwPreviousSignerLength,
		pbCertificate, dwCertificateLength, dwSignType,
		NULL, ppbSigner, pdwSignerLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AppendSigner(
	unsigned char*	pbSigner,
	unsigned long	dwSignerLength,
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength,
	unsigned char*	pbPreviousSign,
	unsigned long	dwPreviousSignLength,
	unsigned char*	*ppbSign,
	unsigned long*	pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AppendSigner(
		NULL, pbSigner, dwSignerLength,
		pbCertificate, dwCertificateLength, NULL,
		pbPreviousSign, dwPreviousSignLength, NULL,
		ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long IsDataInSignedDataAvailable(
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	int*			pbAvailable)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->IsDataInSignedDataAvailable(NULL,
		pbSignedData, dwSignedDataLength, pbAvailable);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetDataFromSignedData(
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetDataFromSignedData(NULL,
		pbSignedData, dwSignedDataLength, ppbData, pdwDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetCertificateFromSignedData(
	unsigned long		dwIndex,
	char*				pszSignedData,
	unsigned char*		pbSignedData,
	unsigned long		dwSignedDataLength,
	char*				**pppszCertInfo,
	unsigned long		*pdwCertInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetCertificateFromSignedData(
		dwIndex, pszSignedData, pbSignedData, 
		dwSignedDataLength, &pInfo, ppbCertificate,
		pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszCertInfo = InfoFields.ppszFields;
	*pdwCertInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long GetSignTimeInfo(
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszTimeInfo,
	unsigned long	*pdwTimeInfo)
{
	PEU_TIME_INFO	pTimeInfo;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->GetSignTimeInfo(
		dwSignIndex, pszSign, pbSign,
		dwSignLength, &pTimeInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pTimeInfo, &InfoFields))
	{
		s_pIface->FreeTimeInfo(pTimeInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeTimeInfo(pTimeInfo);

	*pppszTimeInfo = InfoFields.ppszFields;
	*pdwTimeInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxSignHashValue(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxSignHashValue(
		pvPrivateKeyContext, dwSignAlgo, pbHash,
		dwHashLength, bAppendCert, 
		ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxSignData(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	int				bExternal,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxSignData(
		pvPrivateKeyContext, dwSignAlgo,
		pbData, dwDataLength, bExternal,
		bAppendCert, ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxAppendSignHashValue(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	unsigned char*	pbPreviousSign,
	unsigned long	dwPreviousSignLength,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxAppendSignHashValue(
		pvPrivateKeyContext, dwSignAlgo, pbHash,
		dwHashLength, pbPreviousSign, dwPreviousSignLength,
		bAppendCert, ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError; 

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxAppendSign(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	pbPreviousSign,
	unsigned long	dwPreviousSignLength,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxAppendSign(
		pvPrivateKeyContext, dwSignAlgo,
		pbData, dwDataLength, pbPreviousSign, dwPreviousSignLength,
		bAppendCert, ppbSign, pdwSignLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxCreateSignerEx(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	int				bNoContentTimeStamp,
	unsigned long	dwSignType,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxCreateSignerEx(
		pvPrivateKeyContext, dwSignAlgo, pbHash,
		dwHashLength, bNoContentTimeStamp, dwSignType,
		ppbSigner, pdwSignerLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long RawEnvelopData(
	unsigned char*	pbRecipientCert,
	unsigned long	dwRecipientCertLength,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEnvelopedData,
	unsigned long*	pdwEnvelopedDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->RawEnvelopData(
		pbRecipientCert, dwRecipientCertLength,
		pbData, dwDataLength, NULL,
		ppbEnvelopedData, pdwEnvelopedDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long RawDevelopData(
	unsigned char*	pbEnvelopedData,
	unsigned long	dwEnvelopedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength,
	char*			**pppszSenderInfo,
	unsigned long	*pdwSenderInfo)
{
	unsigned long	dwError;
	EU_ENVELOP_INFO	SenderInfo;
	STRUCT_FIELDS	SenderInfoFields;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->RawDevelopData(
		NULL, pbEnvelopedData, dwEnvelopedDataLength,
		ppbData, pdwDataLength, &SenderInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&SenderInfo, &SenderInfoFields))
	{
		s_pIface->FreeMemory(*ppbData);
		s_pIface->FreeSenderInfo(&SenderInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSenderInfo(&SenderInfo);

	*pppszSenderInfo = SenderInfoFields.ppszFields;
	*pdwSenderInfo = SenderInfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxEnvelopData(
	void*			pvPrivateKeyContext,
	unsigned long	dwRecipientCerts,
	unsigned char*	*ppbRecipientCerts,
	unsigned long*	pdwRecipentCertsLength,
	unsigned long	dwRecipientAppendType,
	int				bSignData,
	int				bAppendCert,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEnvelopData,
	unsigned long*	pdwEnvelopedDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxEnvelopData(
		pvPrivateKeyContext, dwRecipientCerts,
		ppbRecipientCerts, pdwRecipentCertsLength,
		dwRecipientAppendType, bSignData,
		bAppendCert, pbData, dwDataLength,
		ppbEnvelopData, pdwEnvelopedDataLength);
	if (dwError != EU_ERROR_NONE) 
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxEnvelopDataRSA(
	void*			pvPrivateKeyContext,
	unsigned long	dwRecipientCerts,
	unsigned char*	*ppbRecipientCerts,
	unsigned long*	pdwRecipentCertsLength,
	unsigned long	dwContentEncAlgoType,
	int				bSignData,
	int				bAppendCert,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEnvelopedData,
	unsigned long*	pdwEnvelopedDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxEnvelopDataRSA(
		pvPrivateKeyContext, dwRecipientCerts,
		ppbRecipientCerts, pdwRecipentCertsLength,
		dwContentEncAlgoType, bSignData,
		bAppendCert, pbData, dwDataLength,
		ppbEnvelopedData, pdwEnvelopedDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxDevelopData(
	void*			pvPrivateKeyContext,
	char*			pszEnvelopedData,
	unsigned char*  pbEnvelopData,
	unsigned long 	dwEnvelopedDataLength,
	unsigned char*	pbSenderCert,
	unsigned long 	dwSenderCertSize,
	unsigned char* *ppbData,
	unsigned long* 	pdwDataLength,
	char*			**pppszSenderInfo,
	unsigned long	*pdwSenderInfo)
{
	unsigned long	dwError;
	EU_ENVELOP_INFO	SenderInfo;
	STRUCT_FIELDS	InfoFields;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxDevelopData(
		pvPrivateKeyContext, pszEnvelopedData,
		pbEnvelopData, dwEnvelopedDataLength,
		pbSenderCert, dwSenderCertSize, ppbData,
		pdwDataLength,&SenderInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&SenderInfo, &InfoFields))
	{
		s_pIface->CtxFreeSenderInfo(
			pvPrivateKeyContext,
			&SenderInfo);
		s_pIface->CtxFreeMemory(
			pvPrivateKeyContext,
			*ppbData);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeSenderInfo(
		pvPrivateKeyContext,
		&SenderInfo);

	*pppszSenderInfo = InfoFields.ppszFields;
	*pdwSenderInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SessionDestroy(
	void*			pvSession)
{
	 if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->SessionDestroy(pvSession);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SessionGetPeerCertificateInfo(
	void*			pvSession,
	char*			**pppszInfo,
	unsigned long	*pdwInfo)
{
	unsigned long	dwError;
	EU_CERT_INFO	Info;
	STRUCT_FIELDS	InfoFields;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SessionGetPeerCertificateInfo(
		pvSession, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeCertificateInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfo(&Info);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ClientRawMultiSessionCreate(
	unsigned long	dwExpireTime,
	unsigned char*	pbServerData,
	unsigned long	dwServerDataLength,
	void*			*ppvClientSession)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ClientRawMultiSessionCreate(
		dwExpireTime, pbServerData, dwServerDataLength, ppvClientSession);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ServerRawMultiSessionCreate(
	unsigned long	dwExpireTime,
	unsigned long	dwClientsCerts,
	unsigned char*	*ppbClientsCerts,
	unsigned long*	pdwClientsCertsLength,
	unsigned char*	*ppbClientsData,
	unsigned long*	pdwClientsDataLength,
	void*			*ppvServerSession)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ServerRawMultiSessionCreate(dwExpireTime,
		dwClientsCerts, ppbClientsCerts, pdwClientsCertsLength,
		ppbClientsData, pdwClientsDataLength, ppvServerSession);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long RawMultiSessionAddClients(
	void*			pvSession,
	unsigned long	dwClientsCerts,
	unsigned char*	*ppbClientsCerts,
	unsigned long*	pdwClientsCertsLength,
	unsigned char*	*ppbClientsData,
	unsigned long*	pdwClientsDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->RawMultiSessionAddClients(pvSession,
		dwClientsCerts, ppbClientsCerts, pdwClientsCertsLength,
		ppbClientsData, pdwClientsDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SessionEncrypt(
	void*			pvSession,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEncryptedData,
	unsigned long*	pdwEncryptedDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SessionEncrypt(pvSession,
		pbData, dwDataLength,
		ppbEncryptedData, pdwEncryptedDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long SessionDecrypt(
	void*			pvSession,
	unsigned char*	pbEncryptedData,
	unsigned long	dwEncryptedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->SessionDecrypt(pvSession,
		pbEncryptedData, dwEncryptedDataLength,
		ppbData, pdwDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxCreate(
	void*			*ppvContext)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxCreate(ppvContext);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxFree(
	void*			pvContext)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->CtxFree(pvContext);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetType(
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	unsigned long*	pdwXAdESType)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetType(
		pbXAdESData, dwXAdESDataLength, pdwXAdESType);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetSignsCount(
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	unsigned long*	pdwCount)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetSignsCount(
		pbXAdESData, dwXAdESDataLength, pdwCount);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetSignLevel(
	unsigned long	dwSignIndex,
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	unsigned long*	pdwSignLevel)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetSignLevel(
		dwSignIndex, pbXAdESData, dwXAdESDataLength, pdwSignLevel);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetSignerInfo(
	unsigned long		dwSignIndex,
	unsigned char*		pbXAdESData,
	unsigned long		dwXAdESDataLength,
	char*				**pppszInfo,
	unsigned long		*pdwInfo,
	unsigned char*		*ppbCertificate,
	unsigned long*		pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetSignerInfo(
		dwSignIndex, pbXAdESData, dwXAdESDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxXAdESGetSignerInfo(
	void*				pvContext,
	unsigned long		dwSignIndex,
	unsigned char*		pbXAdESData,
	unsigned long		dwXAdESDataLength,
	char*				**pppszInfo,
	unsigned long		*pdwInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxXAdESGetSignerInfo(
		pvContext, dwSignIndex, pbXAdESData, dwXAdESDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->CtxFreeMemory(pvContext, *ppbCertificate);
		s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetSignTimeInfo(
	unsigned long	dwSignIndex,
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	char*			**pppszTimeInfo,
	unsigned long	*pdwTimeInfo)
{
	PEU_TIME_INFO	pTimeInfo;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetSignTimeInfo(
		dwSignIndex, pbXAdESData, dwXAdESDataLength, &pTimeInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pTimeInfo, &InfoFields))
	{
		s_pIface->FreeTimeInfo(pTimeInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeTimeInfo(pTimeInfo);

	*pppszTimeInfo = InfoFields.ppszFields;
	*pdwTimeInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetSignReferences(
	unsigned long	dwSignIndex,
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	char*			**pppszReferences,
	unsigned long	*pdwReferencesCount)
{
	char*			pszReferences;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetSignReferences(
		dwSignIndex, pbXAdESData, dwXAdESDataLength, &pszReferences);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!StringToStringArray(pszReferences,
			pppszReferences, pdwReferencesCount))
	{
		s_pIface->FreeMemory((unsigned char*) pszReferences);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeMemory((unsigned char*) pszReferences);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESGetReference(
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	char*			pszReference,
	unsigned char*	*ppbReference,
	unsigned long*	pdwReferenceLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->XAdESGetReference(
		pbXAdESData, dwXAdESDataLength, pszReference,
		ppbReference, pdwReferenceLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//-----------------------------------------------------------------------------

unsigned long CtxXAdESSignData(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned long	dwXAdESType,
	unsigned long	dwSignLevel,
	char*			*ppszReferences,
	unsigned long	dwReferencesCount,
	unsigned char*	*ppbReferences,
	unsigned long*	pdwReferencesLength,
	unsigned char*	*ppbXAdESData,
	unsigned long*	pdwXAdESDataLength)
{
	char*			pszReferences;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!StringArrayToString(
			(const char**) ppszReferences, dwReferencesCount,
			&pszReferences))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->CtxXAdESSignData(
		pvPrivateKeyContext,
		dwSignAlgo, dwXAdESType, dwSignLevel,
		pszReferences, ppbReferences, pdwReferencesLength,
		ppbXAdESData, pdwXAdESDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszReferences;

		return dwError;
	}

	delete[] pszReferences;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long XAdESVerifyData(
	char*			*ppszReferences,
	unsigned long	dwReferencesCount,
	unsigned char*	*ppbReferences,
	unsigned long*	pdwReferencesLength,
	unsigned long	dwSignIndex,
	unsigned char*	pbXAdESData,
	unsigned long	dwXAdESDataLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	char*			pszReferences;
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!StringArrayToString(
			(const char**) ppszReferences, dwReferencesCount,
			&pszReferences))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->XAdESVerifyData(
		ppszReferences == NULL ? NULL : pszReferences,
		ppbReferences, pdwReferencesLength,
		dwSignIndex, pbXAdESData, dwXAdESDataLength, &Info);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszReferences;

		return dwError;
	}

	if (!Encode(&Info, &InfoFields))
	{
		delete[] pszReferences;

		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	delete[] pszReferences;

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long PDFGetSignType(
	unsigned long	dwSignIndex,
	unsigned char*	pbSignedPDFData,
	unsigned long	dwSignedPDFDataLength,
	unsigned long*	pdwType)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->PDFGetSignType(
		dwSignIndex, pbSignedPDFData,
		dwSignedPDFDataLength, pdwType);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long PDFGetSignsCount(
	unsigned char*	pbSignedPDFData,
	unsigned long	dwSignedPDFDataLength,
	unsigned long*	pdwSignsCount)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->PDFGetSignsCount(
		pbSignedPDFData, dwSignedPDFDataLength, pdwSignsCount);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long PDFGetSignerInfo(
	unsigned long		dwSignIndex,
	unsigned char*		pbSignedPDFData,
	unsigned long		dwSignedPDFDataLength,
	char*				**pppszInfo,
	unsigned long		*pdwInfo,
	unsigned char*		*ppbCertificate,
	unsigned long*		pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->PDFGetSignerInfo(
		dwSignIndex, pbSignedPDFData, dwSignedPDFDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxPDFGetSignerInfo(
	void*				pvContext,
	unsigned long		dwSignIndex,
	unsigned char*		pbSignedPDFData,
	unsigned long		dwSignedPDFDataLength,
	char*				**pppszInfo,
	unsigned long		*pdwInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxPDFGetSignerInfo(
		pvContext, dwSignIndex,
		pbSignedPDFData, dwSignedPDFDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->CtxFreeMemory(pvContext, *ppbCertificate);
		s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long PDFGetSignTimeInfo(
	unsigned long	dwSignIndex,
	unsigned char*	pbSignedPDFData,
	unsigned long	dwSignedPDFDataLength,
	char*			**pppszInfo,
	unsigned long	*pdwInfo)
{
	PEU_TIME_INFO	pTimeInfo;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->PDFGetSignTimeInfo(
		dwSignIndex, pbSignedPDFData,
		dwSignedPDFDataLength, &pTimeInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pTimeInfo, &InfoFields))
	{
		s_pIface->FreeTimeInfo(pTimeInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeTimeInfo(pTimeInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxPDFSignData(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbPDFData,
	unsigned long	dwPDFDataLength,
	unsigned long	dwSignType,
	unsigned char*	*ppbSignedPDFData,
	unsigned long	*pdwSignedPDFDataLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxPDFSignData(
		pvPrivateKeyContext, dwSignAlgo,
		pbPDFData, dwPDFDataLength, dwSignType,
		ppbSignedPDFData, pdwSignedPDFDataLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long PDFVerifyData(
	unsigned long	dwSignIndex,
	unsigned char*	pbSignedPDFData,
	unsigned long	dwPDFDataLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->PDFVerifyData(
		dwSignIndex, pbSignedPDFData,
		dwPDFDataLength, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetASiCType(
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	unsigned long*	pdwASiCType)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetASiCType(
		pbASiCData, dwASiCDataLength, pdwASiCType);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignType(
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	unsigned long*	pdwSignType)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignType(
		pbASiCData, dwASiCDataLength, pdwSignType);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignLevel(
	unsigned long	dwSignIndex,
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	unsigned long*	pdwSignLevel)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignLevel(
		dwSignIndex, pbASiCData,
		dwASiCDataLength, pdwSignLevel);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignsCount(
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	unsigned long*	pdwSignsCount)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignsCount(
		pbASiCData, dwASiCDataLength, pdwSignsCount);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignerInfo(
	unsigned long		dwSignIndex,
	unsigned char*		pbASiCData,
	unsigned long		dwASiCDataLength,
	char*				**pppszCertInfo,
	unsigned long		*pdwCertInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignerInfo(
		dwSignIndex, pbASiCData, dwASiCDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->FreeMemory(*ppbCertificate);
		s_pIface->FreeCertificateInfoEx(pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeCertificateInfoEx(pInfo);

	*pppszCertInfo = InfoFields.ppszFields;
	*pdwCertInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxASiCGetSignerInfo(
	void*				pvContext,
	unsigned long		dwSignIndex,
	unsigned char*		pbASiCData,
	unsigned long		dwASiCDataLength,
	char*				**pppszCertInfo,
	unsigned long		*pdwCertInfo,
	unsigned char*		*ppbCertificate,
	unsigned long		*pdwCertifiacateLength)
{
	PEU_CERT_INFO_EX	pInfo;
	STRUCT_FIELDS		InfoFields;
	unsigned long		dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->CtxASiCGetSignerInfo(
		pvContext, dwSignIndex, pbASiCData, dwASiCDataLength,
		&pInfo, ppbCertificate, pdwCertifiacateLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pInfo, &InfoFields))
	{
		s_pIface->CtxFreeMemory(pvContext, *ppbCertificate);
		s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->CtxFreeCertificateInfoEx(pvContext, pInfo);

	*pppszCertInfo = InfoFields.ppszFields;
	*pdwCertInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignTimeInfo(
	unsigned long	dwSignIndex,
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	char*			**pppszInfo,
	unsigned long	*pdwInfo)
{
	PEU_TIME_INFO	pTimeInfo;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignTimeInfo(
		dwSignIndex, pbASiCData, dwASiCDataLength, &pTimeInfo);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(pTimeInfo, &InfoFields))
	{
		s_pIface->FreeTimeInfo(pTimeInfo);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeTimeInfo(pTimeInfo);

	*pppszInfo = InfoFields.ppszFields;
	*pdwInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetSignReferences(
	unsigned long	dwSignIndex,
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	char*			**pppszReferences,
	unsigned long	*pdwReferencesCount)
{
	char*			pszReferences;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetSignReferences(
		dwSignIndex, pbASiCData,
		dwASiCDataLength, &pszReferences);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!StringToStringArray(pszReferences,
			pppszReferences, pdwReferencesCount))
	{
		s_pIface->FreeMemory((unsigned char*) pszReferences);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeMemory((unsigned char*) pszReferences);

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCGetReference(
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	char*			pszReference,
	unsigned char*	*ppbReference,
	unsigned long*	pdwReferenceLength)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCGetReference(
		pbASiCData, dwASiCDataLength,
		pszReference, ppbReference, pdwReferenceLength);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCIsAllContentCovered(
	unsigned long	dwSignIndex,
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	int*			pbCovered)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCIsAllContentCovered(
		dwSignIndex, pbASiCData, dwASiCDataLength, pbCovered);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxASiCSignData(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned long	dwASiCType,
	unsigned long	dwSignType,
	unsigned long	dwSignLevel,
	char*			*ppszReferences,
	unsigned long	dwReferencesCount,
	unsigned char*	*ppbReferencesData,
	unsigned long*	pdwReferencesDataLength,
	unsigned char*	*ppbASiCData,
	unsigned long	*pdwASiCDataLength)
{
	char*			pszReferences;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!StringArrayToString(
			(const char**) ppszReferences, dwReferencesCount,
			&pszReferences))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->CtxASiCSignData(
		pvPrivateKeyContext, dwSignAlgo,
		dwASiCType, dwSignType, dwSignLevel, 
		pszReferences, ppbReferencesData,
		pdwReferencesDataLength, 
		ppbASiCData, pdwASiCDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszReferences;

		return dwError;
	}

	delete[] pszReferences;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long CtxASiCAppendSign(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned long	dwSignLevel,
	char*			*ppszReferences,
	unsigned long	dwReferencesCount,
	unsigned char*	pbPreviousASiCData,
	unsigned long	dwPreviousASiCDataLength,
	unsigned char*	*ppbASiCData,
	unsigned long	*pdwASiCDataLength)
{
	char*			pszReferences;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	if (!StringArrayToString(
			(const char**) ppszReferences, dwReferencesCount,
			&pszReferences))
	{
		return EU_ERROR_MEMORY_ALLOCATION;
	}

	dwError = s_pIface->CtxASiCAppendSign(
		pvPrivateKeyContext, dwSignAlgo, dwSignLevel, 
		pszReferences, pbPreviousASiCData, dwPreviousASiCDataLength,
		ppbASiCData, pdwASiCDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		delete[] pszReferences;

		return dwError;
	}

	delete[] pszReferences;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long ASiCVerifyData(
	unsigned long	dwSignIndex,
	unsigned char*	pbASiCData,
	unsigned long	dwASiCDataLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo)
{
	EU_SIGN_INFO	Info;
	STRUCT_FIELDS	InfoFields;
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->ASiCVerifyData(
		dwSignIndex, pbASiCData, dwASiCDataLength, &Info);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	if (!Encode(&Info, &InfoFields))
	{
		s_pIface->FreeSignInfo(&Info);

		return EU_ERROR_MEMORY_ALLOCATION;
	}

	s_pIface->FreeSignInfo(&Info);

	*pppszSignInfo = InfoFields.ppszFields;
	*pdwSignInfo = InfoFields.nCount;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxCreate(
	unsigned long	dwAlgo,
	void*			*ppvAlgoContext)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxCreate(
		dwAlgo, ppvAlgoContext);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxGenerateKey(
	void*			pvAlgoContext)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxGenerateKey(
		pvAlgoContext);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxSetKey(
	void*			pvAlgoContext,
	unsigned char*	pbKey,
	unsigned long	dwKey,
	unsigned char*	pbIV,
	unsigned long	dwIV)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxSetKey(
		pvAlgoContext, pbKey, dwKey, pbIV, dwIV);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxGetKeySize(
	void*			pvAlgoContext,
	unsigned long*	pdwKey,
	unsigned long*	pdwIV)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxGetKeySize(
		pvAlgoContext, pdwKey, pdwIV);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxGetKey(
	void*			pvAlgoContext,
	unsigned char*	pbKey,
	unsigned long	dwKey,
	unsigned char*	pbIV,
	unsigned long	dwIV)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxGetKey(
		pvAlgoContext, pbKey, dwKey, pbIV, dwIV);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxEncrypt(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxEncrypt(
		pvAlgoContext, pbData, dwData);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxDecrypt(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxDecrypt(
		pvAlgoContext, pbData, dwData);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxGetDataMAC(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData,
	unsigned char*	pbMAC,
	unsigned long	dwMAC)
{
	unsigned long	dwError;

	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	dwError = s_pIface->AlgoCtxGetDataMAC(
		pvAlgoContext, pbData, dwData, pbMAC, dwMAC);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	return EU_ERROR_NONE;
}

//--------------------------------------------------------------------------------

unsigned long AlgoCtxFree(
	void*			pvAlgoContext)
{
	if (s_pIface == NULL)
		return EU_ERROR_NOT_INITIALIZED;

	s_pIface->AlgoCtxFree(pvAlgoContext);

	return EU_ERROR_NONE;
}

//================================================================================