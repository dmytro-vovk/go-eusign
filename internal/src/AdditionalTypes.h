#ifndef ADDITIONAL_TYPES_H
#define ADDITIONAL_TYPES_H

//================================================================================

#include "EUSignCP.h"

//================================================================================

#define EU_REQUEST_TYPE_UA_DS	1
#define EU_REQUEST_TYPE_UA_KEP	2
#define EU_REQUEST_TYPE_RSA		3
#define EU_REQUEST_TYPE_ECDSA	4

//================================================================================

typedef struct
{
	unsigned char*		pbData;
	unsigned long		dwDataLength;
} EU_BYTE_ARRAY, *PEU_BYTE_ARRAY;

//-----------------------------------------------------------------------------

typedef struct
{
	char			szPath[EU_PATH_MAX_LENGTH];
	int				bCheckCRLs;
	int				bAutoRefresh;
	int				bOwnCRLsOnly;
	int				bFullAndDeltaCRLs;
	int				bAutoDownloadCRLs;
	int				bSaveLoadedCerts;
	unsigned long	dwExpireTime;
} EU_FILE_STORE_SETTINGS, *PEU_FILE_STORE_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bUseProxy;
	int				bAnonymus;
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
	char			szUser[EU_USER_NAME_MAX_LENGTH];
	char			szPassword[EU_PASS_MAX_LENGTH];
	int				bSavePassword;
} EU_PROXY_SETTINGS, *PEU_PROXY_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bUseOCSP;
	int				bBeforeStore;
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
} EU_OCSP_SETTINGS, *PEU_OCSP_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bGetStamps;
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
} EU_TSP_SETTINGS, *PEU_TSP_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bUseLDAP;
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
	int				bAnonymous;
	char			szUser[EU_USER_NAME_MAX_LENGTH];
	char			szPassword[EU_PASS_MAX_LENGTH];
} EU_LDAP_SETTINGS, *PEU_LDAP_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bUseCMP;
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
	char			szCommonName[EU_COMMON_NAME_MAX_LENGTH];
} EU_CMP_SETTINGS, *PEU_CMP_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bEnabled;
} EU_OCSP_ACCESS_INFO_MODE_SETTINGS, *PEU_OCSP_ACCESS_INFO_MODE_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	char			szIssuerCN[EU_ISSUER_MAX_LENGTH];
	char			szAddress[EU_ADDRESS_MAX_LENGTH];
	char			szPort[EU_PORT_MAX_LENGTH];
} EU_OCSP_ACCESS_INFO_SETTINGS, *PEU_OCSP_ACCESS_INFO_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bSystem;
	int				bUseReportAgent;
	char			szReportAgentAddress[EU_ADDRESS_MAX_LENGTH];
	char			szReportAgentPort[EU_ADDRESS_MAX_LENGTH];
	int				bOnlyErrors;
} EU_LOG_SETTINGS, *PEU_LOG_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	int				bOffline;
} EU_MODE_SETTINGS, *PEU_MODE_SETTINGS;

//-----------------------------------------------------------------------------

typedef struct
{
	unsigned long	dwType;
	EU_BYTE_ARRAY	Request;
	char			szFileName[EU_PATH_MAX_LENGTH];
	PEU_CR_INFO		pInfo;
} EU_REQUEST_INFO, *PEU_REQUEST_INFO;

//================================================================================

#endif // ADDITIONAL_TYPES_H
