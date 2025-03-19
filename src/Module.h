#ifndef MODULE_H
#define MODULE_H

//================================================================================

#include <stdlib.h>

//================================================================================

#ifdef __cplusplus
extern "C" {
#endif

unsigned long FreeMemory(
	unsigned char*	pbMemory);

unsigned long FreeCertificatesArray(
	unsigned long	dwCertificatesCount,
	unsigned char	**ppbCertificates,
	unsigned long	*pdwCertificatesLengthes);

unsigned long CtxFreeMemory(
	void*			pvPrivateKeyContext,
	unsigned char*	pbMemory);

unsigned long FreeStructFields(
	char*			*ppszFields,
	unsigned long	dwFields);

unsigned long AllocStructFields(
	unsigned long	dwFields,
	char*			**pppszFields);

//--------------------------------------------------------------------------------

unsigned long GetErrorLangDesc(
	unsigned long	dwError,
	unsigned long	dwLang,
	char*			pszMessage);

//--------------------------------------------------------------------------------

unsigned long BASE64Encode(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	char*			*ppszData);

//--------------------------------------------------------------------------------

unsigned long Initialize();

unsigned long Finalize();

int IsInitialized();

//--------------------------------------------------------------------------------

unsigned long DoesNeedSetSettings(
	int*			pbDoesNeedSetSettings);

unsigned long GetFileStoreSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetFileStoreSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetProxySettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetProxySettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetOCSPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetOCSPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetOCSPAccessInfoModeSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetOCSPAccessInfoModeSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long EnumOCSPAccessInfoSettings(
	unsigned long	dwIndex,
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long GetOCSPAccessInfoSettings(
	char*			pszIssuerCN,
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetOCSPAccessInfoSettings(
	char*			*ppszSettings,
	unsigned long	dwSettings);

unsigned long DeleteOCSPAccessInfoSettings(
	char*			pszIssuerCN);

unsigned long GetTSPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetTSPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetLDAPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetLDAPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetCMPSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetCMPSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetLogSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetLogSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long GetModeSettings(
	char*			**pppszSettings,
	unsigned long	*pdwSettings);

unsigned long SetModeSettings(
	char			**ppszSettings,
	unsigned long	dwSettings);

unsigned long SetRuntimeParameter(
	char*			pszParameterName,
	void*			pvParameterValue,
	unsigned long	dwParameterValueLength);

unsigned long SetOCSPResponseExpireTime(
	unsigned long	dwExpireTime);

//--------------------------------------------------------------------------------

unsigned long SaveCertificate(
	unsigned char	*pbCertificate,
	unsigned long	dwCertificateLength);

unsigned long SaveCertificates(
	unsigned char*	pbCertificates,
	unsigned long	dwCertificatesLength);

unsigned long SaveCertificatesEx(
	unsigned char*	pbCertificates,
	unsigned long	dwCertificatesLength,
	unsigned char*	pbTrustedCertificates,
	unsigned long	dwTrustedCertificatesLength);

unsigned long ParseCertificateEx(
	unsigned char	*pbCertificate,
	unsigned long	dwCertificateLength,
	char*			**pppszInfo,
	unsigned long	*pdwInfo);

unsigned long GetCertificatesByKeyInfo(
	unsigned char*	pbPrivKeyInfo,
	unsigned long	dwPrivKeyInfoLength,
	char*			*ppszCMPServers,
	unsigned long	dwCMPServersCount,
	char*			*ppszCMPServersPorts,
	unsigned long	dwCMPServersPortsCount,
	unsigned char*	*pbCertificates,
	unsigned long*	pdwCertificates);

//--------------------------------------------------------------------------------

unsigned long EnumKeyMediaTypes(
	unsigned long	dwTypeIndex,
	char*			*ppszTypeDescription);

unsigned long EnumKeyMediaDevices(
	unsigned long	dwTypeIndex,
	unsigned long	dwDeviceIndex,
	char*			*ppszDeviceDescription);

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
	unsigned long	*pdwECDSARequest);

unsigned long IsPrivateKeyReaded(
	int				*pbIsPrivateKeyReaded);

unsigned long ReadPrivateKey(
	char			**ppszKeyMedia,
	unsigned long	dwKeyMedia,
	char*			**pppszInfo,
	unsigned long	*pdwInfo);

unsigned long ResetPrivateKey();

unsigned long CtxReadPrivateKey(
	void*			pvContext,
	char*			*ppszKeyMedia,
	unsigned long	pdwKeyMedia,
	void*			*ppvPrivateKeyContext,
	char*			**pppszCertOwnerInfo,
	unsigned long	*pdwCertOwnerInfo);

unsigned long CtxReadPrivateKeyBinary(
	void			*pvContext,
	unsigned char*	pbPrivateKey,
	unsigned long	dwPrivateKeyLength,
	char			*pszPassword,
	void*			*ppvPrivateKeyContext,
	char*			**pppszCertOwnerInfo,
	unsigned long	*pdwCertOwnerInfo);

unsigned long CtxFreePrivateKey(
	void* 			pvPrivateKeyContext);

unsigned long CtxGetOwnCertificate(
	void*			pvPrivateKeyContext,
	unsigned long	dwCertKeyType,
	unsigned long	dwKeyUsage,
	char*			**pppszCertInfo,
	unsigned long	*pdwCertInfo,
	unsigned char*	*ppbCertificate,
	unsigned long	*pdwCertifiacateLength);

unsigned long GetKeyInfo(
	char			**ppszKeyMedia,
	unsigned long	dwKeyMedia,
	unsigned char*	*ppbKeyInfo,
	unsigned long*	pdwKeyInfoLength);

unsigned long GetKeyInfoBinary(
	unsigned char*	pbPrivateKey,
	unsigned long	dwPrivateKeyLength,
	char			*pszPassword,
	unsigned char*	*ppbKeyInfo,
	unsigned long*	pdwKeyInfoLength);

unsigned long EnumJKSPrivateKeys(
	unsigned char*	pbContainer,
	unsigned long	dwContainerLength,
	unsigned long	dwIndex,
	char*			*ppszKeyAlias);

unsigned long GetJKSPrivateKey(
	unsigned char*	pbContainer,
	unsigned long	dwContainerLength,
	char*			pszKeyAlias,
	unsigned char*	*ppbPrivateKey,
	unsigned long*	pdwPrivateKeyLength,
	unsigned long*	pdwCertificatesCount,
	unsigned char*	**ppbCertificates,
	unsigned long*	*ppdwCertificatesLengthes);

//--------------------------------------------------------------------------------

unsigned long CtxHashData(
	void*			pvContext,
	unsigned long	dwHashAlgo,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbHash,
	unsigned long	*pdwHashLength);

//--------------------------------------------------------------------------------

unsigned long GetSignType(
	unsigned long	dwSignIndex,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned long*	pdwSignType);

unsigned long GetSignsCount(
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned long	*pdwCount);

unsigned long GetSigner(
	unsigned long	dwSignIndex,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength);

unsigned long GetSignerInfo(
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszCertInfo,
	unsigned long	*pdwCertInfo,
	unsigned char*	*ppbCertificate,
	unsigned long	*pdwCertifiacateLength);

unsigned long VerifyDataSpecific(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo);

unsigned long VerifyDataInternalSpecific(
	unsigned long	dwSignIndex,
	char*			pszSignedData,
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	unsigned char*	*ppbData,
	unsigned long	*pdwDataLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo);

unsigned long VerifyHashSpecific(
	char*			pszHash,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszSignInfo,
	unsigned long	*pdwSignInfo);

unsigned long CreateEmptySign(
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbSign,
	unsigned long*	pdwSignLength);

unsigned long AppendValidationDataToSignerEx(
	unsigned char*	pbPreviousSigner,
	unsigned long	dwPreviousSignerLength,
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength,
	unsigned long	dwSignType,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength);

unsigned long AppendSigner(
	unsigned char*	pbSigner,
	unsigned long	dwSignerLength,
	unsigned char*	pbCertificate,
	unsigned long	dwCertificateLength,
	unsigned char*	pbPreviousSign,
	unsigned long	dwPreviousSignLength,
	unsigned char*	*ppbSign,
	unsigned long*	pdwSignLength);

unsigned long IsDataInSignedDataAvailable(
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	int*			pbAvailable);

unsigned long GetDataFromSignedData(
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength);

unsigned long GetCertificateFromSignedData(
	unsigned long	dwIndex,
	char*			pszSignedData,
	unsigned char*	pbSignedData,
	unsigned long	dwSignedDataLength,
	char*			**pppszCertInfo,
	unsigned long	*pdwCertInfo,
	unsigned char*	*ppbCertificate,
	unsigned long	*pdwCertifiacateLength);

unsigned long GetSignTimeInfo(
	unsigned long	dwSignIndex,
	char*			pszSign,
	unsigned char*	pbSign,
	unsigned long	dwSignLength,
	char*			**pppszTimeInfo,
	unsigned long	*pdwTimeInfo);

//--------------------------------------------------------------------------------

unsigned long CtxSignHashValue(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength);

unsigned long CtxSignData(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	int				bExternal,
	int				bAppendCert,
	unsigned char*	*ppbSign,
	unsigned long	*pdwSignLength);

unsigned long CtxCreateSignerEx(
	void*			pvPrivateKeyContext,
	unsigned long	dwSignAlgo,
	unsigned char*	pbHash,
	unsigned long	dwHashLength,
	int				bNoContentTimeStamp,
	unsigned long	dwSignType,
	unsigned char*	*ppbSigner,
	unsigned long*	pdwSignerLength);

//--------------------------------------------------------------------------------

unsigned long RawEnvelopData(
	unsigned char*	pbRecipientCert,
	unsigned long	dwRecipientCertLength,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEnvelopedData,
	unsigned long*	pdwEnvelopedDataLength);

unsigned long RawDevelopData(
	unsigned char*	pbEnvelopedData,
	unsigned long	dwEnvelopedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength,
	char*			**pppszSenderInfo,
	unsigned long	*pdwSenderInfo);

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
	unsigned long	*pdwEnvelopedDataLength);

unsigned long CtxDevelopData(
	void*			pvPrivateKeyContext,
	char			*pszEnvelopedData,
	unsigned char*	pbEnvelopData,
	unsigned long	dwEnvelopedDataLength,
	unsigned char	*pbSenderCert,
	unsigned long	dwSenderCertSize,
	unsigned char*	*ppbData,
	unsigned long	*pdwDataLength,
	char*			**pppszSenderInfo,
	unsigned long	*pdwSenderInfo);

//--------------------------------------------------------------------------------

unsigned long SessionDestroy(
	void*			pvSession);

unsigned long SessionGetPeerCertificateInfo(
	void*			pvSession,
	char*			**pppszCertInfo,
	unsigned long	*pdwCertInfo);

unsigned long ClientRawMultiSessionCreate(
	unsigned long	dwExpireTime,
	unsigned char*	pbServerData,
	unsigned long	dwServerDataLength,
	void*			*ppvClientSession);

unsigned long ServerRawMultiSessionCreate(
	unsigned long	dwExpireTime,
	unsigned long	dwClientsCerts,
	unsigned char*	*ppbClientsCerts,
	unsigned long*	pdwClientsCertsLength,
	unsigned char*	*ppbClientsData,
	unsigned long*	pdwClientsDataLength,
	void*			*ppvServerSession);

unsigned long RawMultiSessionAddClients(
	void*			pvSession,
	unsigned long	dwClientsCerts,
	unsigned char*	*ppbClientsCerts,
	unsigned long*	pdwClientsCertsLength,
	unsigned char*	*ppbClientsData,
	unsigned long*	pdwClientsDataLength);

unsigned long SessionEncrypt(
	void*			pvSession,
	unsigned char*	pbData,
	unsigned long	dwDataLength,
	unsigned char*	*ppbEncryptedData,
	unsigned long*	pdwEncryptedDataLength);

unsigned long SessionDecrypt(
	void*			pvSession,
	unsigned char*	pbEncryptedData,
	unsigned long	dwEncryptedDataLength,
	unsigned char*	*ppbData,
	unsigned long*	pdwDataLength);

//--------------------------------------------------------------------------------

unsigned long CtxCreate(
	void*			*ppvContext);

unsigned long CtxFree(
	void*			pvContext);

//--------------------------------------------------------------------------------

unsigned long AlgoCtxCreate(
	unsigned long	dwAlgo,
	void*			*ppvAlgoContext);

unsigned long AlgoCtxGenerateKey(
	void*			pvAlgoContext);

unsigned long AlgoCtxSetKey(
	void*			pvAlgoContext,
	unsigned char*	pbKey,
	unsigned long	dwKey,
	unsigned char*	pbIV,
	unsigned long	dwIV);

unsigned long AlgoCtxGetKeySize(
	void*			pvAlgoContext,
	unsigned long*	pdwKey,
	unsigned long*	pdwIV);

unsigned long AlgoCtxGetKey(
	void*			pvAlgoContext,
	unsigned char*	pbKey,
	unsigned long	dwKey,
	unsigned char*	pbIV,
	unsigned long	dwIV);

unsigned long AlgoCtxEncrypt(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData);

unsigned long AlgoCtxDecrypt(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData);

unsigned long AlgoCtxGetDataMAC(
	void*			pvAlgoContext,
	unsigned char*	pbData,
	unsigned long	dwData,
	unsigned char*	pbMAC,
	unsigned long	dwMAC);

unsigned long AlgoCtxFree(
	void*			pvAlgoContext);

//--------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

//================================================================================

#endif // MODULE_H
