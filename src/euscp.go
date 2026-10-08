package euscp

// #cgo CFLAGS:
// #cgo CXXFLAGS: -g -Wall
// #cgo linux CXXFLAGS: -DOS_NIX
// #cgo darwin CXXFLAGS: -DOS_NIX
// #cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux/64
// #cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux/arm
// #cgo linux,386 LDFLAGS: -L${SRCDIR}/lib/linux/32
// #cgo linux LDFLAGS: -ldl -losi
// #cgo darwin LDFLAGS: -ldl -L${SRCDIR}/lib/darwin
// #cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}/lib/darwin -losi
// #include <stdlib.h>
// #include "Module.h"
import (
	"C"
)
import (
	"unsafe"
)

var lang = LangDefault

// Initialize using library
func Initialize() error {
	cError := C.Initialize()

	return makeError(cError, lang)
}

// Finalize using library
func Finalize() error {
	cError := C.Finalize()

	return makeError(cError, lang)
}

// IsInitialized check the status of the library
func IsInitialized() bool {
	cIsInitialized := C.IsInitialized()

	return cIsInitialized != 0
}

// DoesNeedSetSettings gets signs of the need to set parameters
func DoesNeedSetSettings() (bool, error) {
	var cDoesNeedSetSettings C.int

	cError := C.DoesNeedSetSettings(&cDoesNeedSetSettings)
	if cError != ErrorNone {
		return false, makeError(cError, lang)
	}

	return cDoesNeedSetSettings != 0, makeError(cError, lang)
}

// GetFileStoreSettings gets file store settings
func GetFileStoreSettings() (*FileStoreSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetFileStoreSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeFileStoreSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetFileStoreSettings sets file store settings
func SetFileStoreSettings(settings *FileStoreSettings) error {
	cSettings, cSettingsSize := encodeFileStoreSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetFileStoreSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetProxySettings gets proxy settings
func GetProxySettings() (*ProxySettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetProxySettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeProxySettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetProxySettings sets proxy settings
func SetProxySettings(settings *ProxySettings) error {
	cSettings, cSettingsSize := encodeProxySettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetProxySettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetOCSPSettings gets OCSP settings
func GetOCSPSettings() (*OCSPSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetOCSPSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeOCSPSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetOCSPSettings sets OCSP settings
func SetOCSPSettings(settings *OCSPSettings) error {
	cSettings, cSettingsSize := encodeOCSPSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetOCSPSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetOCSPAccessInfoModeSettings gets OCSP access info mode settings
func GetOCSPAccessInfoModeSettings() (*OCSPAccessInfoModeSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetOCSPAccessInfoModeSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeOCSPAccessInfoModeSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetOCSPAccessInfoModeSettings sets OCSP access info mode settings
func SetOCSPAccessInfoModeSettings(settings *OCSPAccessInfoModeSettings) error {
	cSettings, cSettingsSize := encodeOCSPAccessInfoModeSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetOCSPAccessInfoModeSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// EnumOCSPAccessInfoSettings enums OCSP access info settings
func EnumOCSPAccessInfoSettings(index int) (*OCSPAccessInfoSettings, error) {
	cIndex := C.ulong(index)
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.EnumOCSPAccessInfoSettings(
		cIndex, &cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeOCSPAccessInfoSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// GetOCSPAccessInfoSettings gets ocsp access info settings
func GetOCSPAccessInfoSettings(issuerCN string) (*OCSPAccessInfoSettings, error) {
	cIssuerCN := C.CString(issuerCN)
	defer C.free(unsafe.Pointer(cIssuerCN))
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetOCSPAccessInfoSettings(
		cIssuerCN, &cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeOCSPAccessInfoSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetOCSPAccessInfoSettings sets ocsp access info settings
func SetOCSPAccessInfoSettings(settings *OCSPAccessInfoSettings) error {
	cSettings, cSettingsSize := encodeOCSPAccessInfoSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetOCSPAccessInfoSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// DeleteOCSPAccessInfoSettings delete ocsp access info settings
func DeleteOCSPAccessInfoSettings(issuerCN string) error {
	cIssuerCN := C.CString(issuerCN)
	defer C.free(unsafe.Pointer(cIssuerCN))

	cError := C.DeleteOCSPAccessInfoSettings(cIssuerCN)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetTSPSettings gets TSP settings
func GetTSPSettings() (*TSPSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetTSPSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeTSPSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetTSPSettings sets TSP settings
func SetTSPSettings(settings *TSPSettings) error {
	cSettings, cSettingsSize := encodeTSPSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetTSPSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetLDAPSettings gets LDAP settings
func GetLDAPSettings() (*LDAPSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetLDAPSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeLDAPSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetLDAPSettings sets LDAP settings
func SetLDAPSettings(settings *LDAPSettings) error {
	cSettings, cSettingsSize := encodeLDAPSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetLDAPSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetCMPSettings gets CMP settings
func GetCMPSettings() (*CMPSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetCMPSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeCMPSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetCMPSettings sets CMP settings
func SetCMPSettings(settings *CMPSettings) error {
	cSettings, cSettingsSize := encodeCMPSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetCMPSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetLogSettings gets log settings
func GetLogSettings() (*LogSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetLogSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeLogSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetLogSettings sets log settings
func SetLogSettings(settings *LogSettings) error {
	cSettings, cSettingsSize := encodeLogSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetLogSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// GetModeSettings gets mode settings
func GetModeSettings() (*ModeSettings, error) {
	var cSettings **C.char
	var cSettingsSize C.ulong

	cError := C.GetModeSettings(&cSettings, &cSettingsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	settings := decodeModeSettings(cSettings, cSettingsSize)
	C.FreeStructFields(cSettings, cSettingsSize)

	return settings, makeError(cError, lang)
}

// SetModeSettings sets mode settings
func SetModeSettings(settings *ModeSettings) error {
	cSettings, cSettingsSize := encodeModeSettings(settings)
	defer C.FreeStructFields(cSettings, cSettingsSize)

	cError := C.SetModeSettings(cSettings, cSettingsSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// SetRuntimeParameterInt configures integer runtime
// parameters of the cryptographic library
func SetRuntimeParameterInt(name string, value int) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	cValue := C.int(value)
	cValueSize := C.ulong(unsafe.Sizeof(C.int(0)))

	cError := C.SetRuntimeParameter(
		cName, unsafe.Pointer(&cValue), cValueSize)

	return makeError(cError, lang)
}

// SetRuntimeParameterBool configures boolean runtime
// parameters of the cryptographic library
func SetRuntimeParameterBool(name string, value bool) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	cValue := toCBool(value)
	cValueSize := C.ulong(unsafe.Sizeof(C.int(0)))

	cError := C.SetRuntimeParameter(
		cName, unsafe.Pointer(&cValue), cValueSize)

	return makeError(cError, lang)
}

// SetOCSPResponseExpireTime set the confidence interval value (in seconds)
// to the OCSP response contained in the signed data
func SetOCSPResponseExpireTime(expireTime int) error {
	cExpireTime := C.ulong(expireTime)

	cError := C.SetOCSPResponseExpireTime(cExpireTime)

	return makeError(cError, lang)
}

// SaveCertificate saves certificate
func SaveCertificate(certificate []byte) error {
	cCertificate, cCertificateLength := cbuf(certificate)

	cError := C.SaveCertificate(
		cCertificate, cCertificateLength)

	return makeError(cError, lang)
}

// SaveCertificates saves certificates
func SaveCertificates(certificates []byte) error {
	cCertificates, cCertificatesLength := cbuf(certificates)

	cError := C.SaveCertificates(
		cCertificates, cCertificatesLength)

	return makeError(cError, lang)
}

// SaveCertificatesEx save certificates
func SaveCertificatesEx(certificates []byte) error {
	cCertificates, cCertificatesLength := cbuf(certificates)

	cError := C.SaveCertificatesEx(
		cCertificates, cCertificatesLength, nil, 0)

	return makeError(cError, lang)
}

// ParseCertificateEx gets certificate info
func ParseCertificateEx(certificate []byte) (*CertInfoEx, error) {
	cCertificate, cCertificateLength := cbuf(certificate)
	var cInfo **C.char
	var cInfoSize C.ulong

	cError := C.ParseCertificateEx(
		cCertificate, cCertificateLength, &cInfo, &cInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	info := decodeCertInfoEx(cInfo, cInfoSize)
	C.FreeStructFields(cInfo, cInfoSize)

	return info, makeError(cError, lang)
}

// GetCertificatesByKeyInfo gets certificates by key info using CMP servers
func GetCertificatesByKeyInfo(privKeyInfo []byte, cmpServers []string, cmpServersPorts []string) ([]byte, error) {
	cPrivKeyInfo, cPrivKeyInfoSize := cbuf(privKeyInfo)
	cCMPServers, cCMPServersSize := cStrings(cmpServers)
	defer C.FreeStructFields(cCMPServers, cCMPServersSize)
	cCMPServersPorts, cCMPServersPortsSize := cStrings(cmpServersPorts)
	defer C.FreeStructFields(cCMPServersPorts, cCMPServersPortsSize)
	var cCerts *C.uchar
	var cCertsSize C.ulong

	cError := C.GetCertificatesByKeyInfo(
		cPrivKeyInfo, cPrivKeyInfoSize,
		cCMPServers, cCMPServersSize,
		cCMPServersPorts, cCMPServersPortsSize,
		&cCerts, &cCertsSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	certs := C.GoBytes(unsafe.Pointer(cCerts), C.int(cCertsSize))
	C.FreeMemory(cCerts)

	return certs, makeError(cError, lang)
}

// EnumKeyMediaTypes enums key media types
func EnumKeyMediaTypes(typeIndex int) (string, error) {
	cTypeIndex := C.ulong(typeIndex)
	var cDescr *C.char

	cError := C.EnumKeyMediaTypes(cTypeIndex, &cDescr)
	if cError != ErrorNone {
		return "", makeError(cError, lang)
	}

	typeDescription := C.GoString(cDescr)
	C.free(unsafe.Pointer(cDescr))

	return typeDescription, makeError(cError, lang)
}

// EnumKeyMediaDevices enums key media devices
func EnumKeyMediaDevices(typeIndex int, deviceIndex int) (string, error) {
	cTypeIndex := C.ulong(typeIndex)
	cDeviceIndex := C.ulong(deviceIndex)
	var cDescr *C.char

	cError := C.EnumKeyMediaDevices(
		cTypeIndex, cDeviceIndex, &cDescr)
	if cError != ErrorNone {
		return "", makeError(cError, lang)
	}

	deviceDescription := C.GoString(cDescr)
	C.free(unsafe.Pointer(cDescr))

	return deviceDescription, makeError(cError, lang)
}

// GeneratePrivateKey2 Generating a private key on key media
func GeneratePrivateKey2(
	keyMedia *KeyMedia, setKeyMediaPassword bool,
	uaKeysType int, uaDSKeysSpec int, uaKEPKeysSpec int,
	uaParamsPath string, intKeysType int, rsaKeysSpec int,
	rsaParamsPath string, ecdsaKeysSpec int, ecdsaParamsPath string,
	userInfo *UserInfo, addExtKeyUsages bool, extKeyUsages string) ([]RequestInfo, error) {
	cKeyMedia, cKeyMediaSize := encodeKeyMedia(keyMedia)
	defer C.FreeStructFields(cKeyMedia, cKeyMediaSize)
	cUserInfo, cUserInfoSize := encodeUserInfo(userInfo)
	defer C.FreeStructFields(cUserInfo, cUserInfoSize)

	cUAParamsPath := C.CString(uaParamsPath)
	defer C.free(unsafe.Pointer(cUAParamsPath))
	cRSAParamsPath := C.CString(rsaParamsPath)
	defer C.free(unsafe.Pointer(cRSAParamsPath))
	cECDSAParamsPath := C.CString(ecdsaParamsPath)
	defer C.free(unsafe.Pointer(cECDSAParamsPath))

	cSetKeyMediaPassword := toCBool(setKeyMediaPassword)

	cUAKeysType := C.ulong(uaKeysType)
	cUADSKeysSpec := C.ulong(uaDSKeysSpec)
	cUAKEPKeysSpec := C.ulong(uaKEPKeysSpec)

	cIntKeysType := C.ulong(intKeysType)
	cRSAKeysSpec := C.ulong(rsaKeysSpec)
	cECDSAKeysSpec := C.ulong(ecdsaKeysSpec)

	var cRequests [4](**C.char)
	var cRequestsSizes [4](C.ulong)
	var cExtKeyUsages *C.char = nil

	if addExtKeyUsages {
		cExtKeyUsages = C.CString(extKeyUsages)
		defer C.free(unsafe.Pointer(cExtKeyUsages))
	}

	if keyMedia == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.GeneratePrivateKey2(
		cKeyMedia, cKeyMediaSize, cSetKeyMediaPassword,
		cUAKeysType, cUADSKeysSpec, cUAKEPKeysSpec, cUAParamsPath,
		cIntKeysType, cRSAKeysSpec, cRSAParamsPath, cECDSAKeysSpec,
		cECDSAParamsPath, cUserInfo, cUserInfoSize, cExtKeyUsages,
		&cRequests[0], &cRequestsSizes[0], &cRequests[1], &cRequestsSizes[1],
		&cRequests[2], &cRequestsSizes[2], &cRequests[3], &cRequestsSizes[3])
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	var requests []RequestInfo

	for i := range cRequests {
		if cRequests[i] != nil {
			request := decodeRequestInfo(
				cRequests[i], cRequestsSizes[i])
			C.FreeStructFields(cRequests[i], cRequestsSizes[i])
			requests = append(requests, *request)
		}
	}

	return requests, makeError(cError, lang)
}

// IsPrivateKeyReaded checks is private key readed to global library context
func IsPrivateKeyReaded() (bool, error) {
	var cIsPrivateKeyReaded C.int

	cError := C.IsPrivateKeyReaded(&cIsPrivateKeyReaded)
	if cError != ErrorNone {
		return false, makeError(cError, lang)
	}

	return cIsPrivateKeyReaded != 0, makeError(cError, lang)
}

// ReadPrivateKey reads private key from key media to global library context
func ReadPrivateKey(keyMedia *KeyMedia) (*CertOwnerInfo, error) {
	cKeyMedia, cKeyMediaSize := encodeKeyMedia(keyMedia)
	defer C.FreeStructFields(cKeyMedia, cKeyMediaSize)
	var cInfo **C.char
	var cInfoSize C.ulong

	cError := C.ReadPrivateKey(
		cKeyMedia, cKeyMediaSize, &cInfo, &cInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	info := decodeCertOwnerInfo(cInfo, cInfoSize)
	C.FreeStructFields(cInfo, cInfoSize)

	return info, makeError(cError, lang)
}

// ResetPrivateKey resets private key global library context
func ResetPrivateKey() error {
	cError := C.ResetPrivateKey()

	return makeError(cError, lang)
}

// CtxReadPrivateKey reads private key from key media
func CtxReadPrivateKey(context *Context, keyMedia *KeyMedia) (*PrivateKeyContext, *CertOwnerInfo, error) {
	cKeyMedia, cKeyMediaSize := encodeKeyMedia(keyMedia)
	defer C.FreeStructFields(cKeyMedia, cKeyMediaSize)
	var cInfo **C.char
	var cInfoSize C.ulong

	if context == nil {
		return nil, nil, makeError(ErrorBadParameter, lang)
	}

	pkContext := new(PrivateKeyContext)

	cError := C.CtxReadPrivateKey(context.Handle, cKeyMedia, cKeyMediaSize, &pkContext.Handle, &cInfo, &cInfoSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	info := decodeCertOwnerInfo(cInfo, cInfoSize)
	C.FreeStructFields(cInfo, cInfoSize)

	return pkContext, info, makeError(cError, lang)
}

// CtxReadPrivateKeyBinary reads private key from binary data
func CtxReadPrivateKeyBinary(context *Context, privateKey []byte, password string) (*PrivateKeyContext, *CertOwnerInfo, error) {
	cPrivateKey, cPrivateKeySize := cbuf(privateKey)
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))
	var cInfo **C.char
	var cInfoSize C.ulong

	if context == nil {
		return nil, nil, makeError(ErrorBadParameter, lang)
	}

	pkContext := new(PrivateKeyContext)

	cError := C.CtxReadPrivateKeyBinary(context.Handle,
		cPrivateKey, cPrivateKeySize, cPassword,
		&pkContext.Handle, &cInfo, &cInfoSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	info := decodeCertOwnerInfo(cInfo, cInfoSize)
	C.FreeStructFields(cInfo, cInfoSize)

	return pkContext, info, makeError(cError, lang)
}

// CtxFreePrivateKey frees private key
func CtxFreePrivateKey(pkContext *PrivateKeyContext) error {
	if pkContext == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxFreePrivateKey(pkContext.Handle)

	return makeError(cError, lang)
}

// CtxGetOwnCertificate gets own certificate
func CtxGetOwnCertificate(pkContext *PrivateKeyContext, certKeyType int, keyUsage int) (*CertInfoEx, []byte, error) {
	cCertKeyType := C.ulong(certKeyType)
	cKeyUsage := C.ulong(keyUsage)
	var cCertInfoEx **C.char
	var cCertInfoExSize C.ulong
	var cCert *C.uchar
	var cCertSize C.ulong

	if pkContext == nil {
		return nil, nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxGetOwnCertificate(
		pkContext.Handle, cCertKeyType, cKeyUsage,
		&cCertInfoEx, &cCertInfoExSize, &cCert, &cCertSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	certInfoEx := decodeCertInfoEx(cCertInfoEx, cCertInfoExSize)
	C.FreeStructFields(cCertInfoEx, cCertInfoExSize)

	cert := C.GoBytes(unsafe.Pointer(cCert), C.int(cCertSize))
	C.CtxFreeMemory(pkContext.Handle, cCert)

	return certInfoEx, cert, makeError(cError, lang)
}

// GetKeyInfo gets key information to get key certificates from CMP
func GetKeyInfo(keyMedia *KeyMedia) ([]byte, error) {
	cKeyMedia, cKeyMediaSize := encodeKeyMedia(keyMedia)
	defer C.FreeStructFields(cKeyMedia, cKeyMediaSize)
	var cKeyInfo *C.uchar
	var cKeyInfoSize C.ulong

	cError := C.GetKeyInfo(
		cKeyMedia, cKeyMediaSize, &cKeyInfo, &cKeyInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	keyInfo := C.GoBytes(unsafe.Pointer(cKeyInfo), C.int(cKeyInfoSize))
	C.FreeMemory(cKeyInfo)

	return keyInfo, makeError(cError, lang)
}

// GetKeyInfo gets key information to get key certificates from CMP
func GetKeyInfoBinary(privateKey []byte, password string) ([]byte, error) {
	cPrivateKey, cPrivateKeySize := cbuf(privateKey)
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))
	var cKeyInfo *C.uchar
	var cKeyInfoSize C.ulong

	cError := C.GetKeyInfoBinary(
		cPrivateKey, cPrivateKeySize, cPassword,
		&cKeyInfo, &cKeyInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	keyInfo := C.GoBytes(unsafe.Pointer(cKeyInfo), C.int(cKeyInfoSize))
	C.FreeMemory(cKeyInfo)

	return keyInfo, makeError(cError, lang)
}

// EnumJKSPrivateKeys enums the private keys in the JKS container
func EnumJKSPrivateKeys(container []byte, index int) (string, error) {
	cContainer, cContainerLength := cbuf(container)
	cIndex := C.ulong(index)
	var cKeyAlias *C.char

	cError := C.EnumJKSPrivateKeys(cContainer,
		cContainerLength, cIndex, &cKeyAlias)
	if cError != ErrorNone {
		return "", makeError(cError, lang)
	}

	keyAlias := C.GoString(cKeyAlias)
	C.free(unsafe.Pointer(cKeyAlias))

	return keyAlias, makeError(cError, lang)
}

// GetJKSPrivateKey gets the private key from the JKS container
func GetJKSPrivateKey(container []byte, keyAlias string) ([]byte, [][]byte, error) {
	cContainer, cContainerLength := cbuf(container)
	cKeyAlias := C.CString(keyAlias)
	defer C.free(unsafe.Pointer(cKeyAlias))
	var cPrivateKey *C.uchar
	var cPrivateKeySize C.ulong
	var cCertificatesCount C.ulong
	var cCertificates **C.uchar
	var cCertificatesSizes *C.ulong

	cError := C.GetJKSPrivateKey(
		cContainer, cContainerLength, cKeyAlias,
		&cPrivateKey, &cPrivateKeySize,
		&cCertificatesCount, &cCertificates, &cCertificatesSizes)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	privateKey := C.GoBytes(unsafe.Pointer(cPrivateKey), C.int(cPrivateKeySize))
	C.FreeMemory(cPrivateKey)

	certificates := gobufs(cCertificatesCount, cCertificates, cCertificatesSizes)
	C.FreeCertificatesArray(cCertificatesCount, cCertificates, cCertificatesSizes)

	return privateKey, certificates, makeError(cError, lang)
}

// CtxHashData hashes data with context
func CtxHashData(context *Context, hashAlgo int, data []byte) ([]byte, error) {
	cData, cDataSize := cbuf(data)
	cHashAlgo := C.ulong(hashAlgo)
	var cHash *C.uchar
	var cHashSize C.ulong

	if context == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxHashData(context.Handle, cHashAlgo,
		cData, cDataSize, &cHash, &cHashSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	hash := C.GoBytes(unsafe.Pointer(cHash), C.int(cHashSize))
	C.CtxFreeMemory(context.Handle, cHash)

	return hash, makeError(cError, lang)
}

// GetSignType gets information about the signature type
func GetSignType(signIndex int, sign []byte) (int, error) {
	cSign, cSignLength := cbuf(sign)
	cSignIndex := C.ulong(signIndex)
	var cSignType C.ulong

	cError := C.GetSignType(cSignIndex,
		cSign, cSignLength, &cSignType)
	if cError != ErrorNone {
		return 0, makeError(cError, lang)
	}

	return int(cSignType), makeError(cError, lang)
}

// GetSignsCount returns number of signers from signature
func GetSignsCount(sign []byte) (int, error) {
	cSign, cSignSize := cbuf(sign)
	var cSignsCount C.ulong

	cError := C.GetSignsCount(nil, cSign, cSignSize, &cSignsCount)
	if cError != ErrorNone {
		return 0, makeError(cError, lang)
	}

	return int(cSignsCount), makeError(cError, lang)
}

// GetSigner gets the signer from signature
func GetSigner(signIndex int, sign []byte) ([]byte, error) {
	cSign, cSignLength := cbuf(sign)
	cSignIndex := C.ulong(signIndex)
	var cSignerInfo *C.uchar
	var cSignerInfoLength C.ulong

	cError := C.GetSigner(cSignIndex,
		cSign, cSignLength, &cSignerInfo, &cSignerInfoLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	signerInfo := C.GoBytes(unsafe.Pointer(cSignerInfo), C.int(cSignerInfoLength))
	C.FreeMemory(cSignerInfo)

	return signerInfo, makeError(cError, lang)
}

// GetSignerInfo gets signer information from sign for signIndex
func GetSignerInfo(signIndex int, sign []byte) (*CertInfoEx, []byte, error) {
	cSignIndex := C.ulong(signIndex)
	cSign, cSignSize := cbuf(sign)
	var cCertInfoEx **C.char
	var cCertInfoExSize C.ulong
	var cCert *C.uchar
	var cCertSize C.ulong

	cError := C.GetSignerInfo(
		cSignIndex, nil, cSign, cSignSize,
		&cCertInfoEx, &cCertInfoExSize, &cCert, &cCertSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	certInfoEx := decodeCertInfoEx(cCertInfoEx, cCertInfoExSize)
	C.FreeStructFields(cCertInfoEx, cCertInfoExSize)

	cert := C.GoBytes(unsafe.Pointer(cCert), C.int(cCertSize))
	C.FreeMemory(cCert)

	return certInfoEx, cert, makeError(cError, lang)
}

// VerifyDataSpecific verifies sign of data for signIndex signer
func VerifyDataSpecific(data []byte, signIndex int, sign []byte) (*SignerInfo, error) {
	cData, cDataSize := cbuf(data)
	cSignIndex := C.ulong(signIndex)
	cSign, cSignSize := cbuf(sign)
	var cSignInfo **C.char
	var cSignInfoSize C.ulong

	cError := C.VerifyDataSpecific(
		cData, cDataSize, cSignIndex,
		nil, cSign, cSignSize, &cSignInfo, &cSignInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	signInfo := decodeSignerInfo(cSignInfo, cSignInfoSize)
	C.FreeStructFields(cSignInfo, cSignInfoSize)

	return signInfo, makeError(cError, lang)
}

// VerifyDataInternalSpecific verifies sign for signIndex signer
func VerifyDataInternalSpecific(signIndex int, sign []byte) (*SignerInfo, []byte, error) {
	cSignIndex := C.ulong(signIndex)
	cSign, cSignSize := cbuf(sign)
	var cData *C.uchar
	var cDataSize C.ulong
	var cSignInfo **C.char
	var cSignInfoSize C.ulong

	cError := C.VerifyDataInternalSpecific(
		cSignIndex, nil, cSign, cSignSize, &cData, &cDataSize,
		&cSignInfo, &cSignInfoSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(cDataSize))
	C.FreeMemory(cData)

	signInfo := decodeSignerInfo(cSignInfo, cSignInfoSize)
	C.FreeStructFields(cSignInfo, cSignInfoSize)

	return signInfo, data, makeError(cError, lang)
}

// VerifyHashSpecific verifies sign of hash for signIndex signer
func VerifyHashSpecific(hash []byte, signIndex int, sign []byte) (*SignerInfo, error) {
	cHash, cHashSize := cbuf(hash)
	cSignIndex := C.ulong(signIndex)
	cSign, cSignSize := cbuf(sign)
	var cSignInfo **C.char
	var cSignInfoSize C.ulong

	cError := C.VerifyHashSpecific(
		nil, cHash, cHashSize, cSignIndex,
		nil, cSign, cSignSize, &cSignInfo, &cSignInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	signInfo := decodeSignerInfo(cSignInfo, cSignInfoSize)
	C.FreeStructFields(cSignInfo, cSignInfoSize)

	return signInfo, makeError(cError, lang)
}

// CreateEmptySign creates an empty signature
func CreateEmptySign(data []byte) ([]byte, error) {
	var cData *C.uchar
	var cDataLength C.ulong
	var cSign *C.uchar
	var cSignLength C.ulong

	cData, cDataLength = cbuf(data)

	cError := C.CreateEmptySign(
		cData, cDataLength, &cSign, &cSignLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	sign := C.GoBytes(unsafe.Pointer(cSign), C.int(cSignLength))
	C.FreeMemory(cSign)

	return sign, makeError(cError, lang)
}

// AppendValidationDataToSignerEx Adds additional verification
// information to the signer information
func AppendValidationDataToSignerEx(previousSigner []byte, certificate []byte, signType int) ([]byte, error) {
	cPreviousSigner, cPreviousSignerLength := cbuf(previousSigner)
	cCertificate, cCertificateLength := cbuf(certificate)
	cSignType := C.ulong(signType)
	var cSignerInfo *C.uchar
	var cSignerInfoLength C.ulong

	cError := C.AppendValidationDataToSignerEx(
		cPreviousSigner, cPreviousSignerLength,
		cCertificate, cCertificateLength, cSignType,
		&cSignerInfo, &cSignerInfoLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	signerInfo := C.GoBytes(unsafe.Pointer(cSignerInfo), C.int(cSignerInfoLength))
	C.FreeMemory(cSignerInfo)

	return signerInfo, makeError(cError, lang)
}

// AppendSigner adds information about the signer to the signature
func AppendSigner(signer []byte, certificate []byte, previousSign []byte) ([]byte, error) {
	cSigner, cSignerLength := cbuf(signer)
	cCertificate, cCertificateLength := cbuf(certificate)
	cPreviousSign, cPreviousSignLength := cbuf(previousSign)
	var cSign *C.uchar
	var cSignLength C.ulong

	cError := C.AppendSigner(
		cSigner, cSignerLength,
		cCertificate, cCertificateLength,
		cPreviousSign, cPreviousSignLength,
		&cSign, &cSignLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	sign := C.GoBytes(unsafe.Pointer(cSign), C.int(cSignLength))
	C.FreeMemory(cSign)

	return sign, makeError(cError, lang)
}

// IsDataInSignedDataAvailable gets information about
// the presence of data in signed data
func IsDataInSignedDataAvailable(signedData []byte) (bool, error) {
	cSignedData, cSignedDataLength := cbuf(signedData)
	var cIsAvaliable C.int

	cError := C.IsDataInSignedDataAvailable(
		cSignedData, cSignedDataLength, &cIsAvaliable)

	return cIsAvaliable != 0, makeError(cError, lang)
}

// GetDataFromSignedData gets the data contained in signed data
func GetDataFromSignedData(signedData []byte) ([]byte, error) {
	cSignedData, cSignedDataLength := cbuf(signedData)
	var cData *C.uchar
	var cDataLength C.ulong

	cError := C.GetDataFromSignedData(
		cSignedData, cSignedDataLength,
		&cData, &cDataLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(cDataLength))
	C.FreeMemory(cData)

	return data, makeError(cError, lang)
}

// GetCertificateFromSignedData gets certificate from signedData or
// p7b archive by index
func GetCertificateFromSignedData(index int, signedData []byte) (*CertInfoEx, []byte, error) {
	cIndex := C.ulong(index)
	cSignedData, cSignedDataSize := cbuf(signedData)
	var cCertInfoEx **C.char
	var cCertInfoExSize C.ulong
	var cCert *C.uchar
	var cCertSize C.ulong

	cError := C.GetCertificateFromSignedData(
		cIndex, nil, cSignedData, cSignedDataSize,
		&cCertInfoEx, &cCertInfoExSize, &cCert, &cCertSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	certInfoEx := decodeCertInfoEx(cCertInfoEx, cCertInfoExSize)
	C.FreeStructFields(cCertInfoEx, cCertInfoExSize)

	cert := C.GoBytes(unsafe.Pointer(cCert), C.int(cCertSize))
	C.FreeMemory(cCert)

	return certInfoEx, cert, makeError(cError, lang)
}

// GetSignTimeInfo gets sign information from sign for signIndex
func GetSignTimeInfo(signIndex int, sign []byte) (*TimeInfo, error) {
	cSignIndex := C.ulong(signIndex)
	cSign, cSignSize := cbuf(sign)
	var cTimeInfo **C.char
	var cTimeInfoSize C.ulong

	cError := C.GetSignTimeInfo(
		cSignIndex, nil, cSign, cSignSize,
		&cTimeInfo, &cTimeInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	timeInfo := decodeTimeInfo(cTimeInfo, cTimeInfoSize)
	C.FreeStructFields(cTimeInfo, cTimeInfoSize)

	return timeInfo, makeError(cError, lang)
}

// CtxSignHashValue signs hash value
func CtxSignHashValue(pkContext *PrivateKeyContext, signAlgo int, hash []byte, appendCert bool) ([]byte, error) {
	cHash, cHashLength := cbuf(hash)
	cSignAlgo := C.ulong(signAlgo)
	cAppendCert := toCBool(appendCert)
	var cSign *C.uchar
	var cSignSize C.ulong

	if pkContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxSignHashValue(
		pkContext.Handle, cSignAlgo, cHash, cHashLength,
		cAppendCert, &cSign, &cSignSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	sign := C.GoBytes(unsafe.Pointer(cSign), C.int(cSignSize))
	C.CtxFreeMemory(pkContext.Handle, cSign)

	return sign, makeError(cError, lang)
}

// CtxSignData signs data
func CtxSignData(pkContext *PrivateKeyContext, signAlgo int, data []byte, external bool, appendCert bool) ([]byte, error) {
	cData, cDataLength := cbuf(data)
	cSignAlgo := C.ulong(signAlgo)
	cAppendCert := toCBool(appendCert)
	cExternal := toCBool(external)
	var cSign *C.uchar
	var cSignSize C.ulong

	if pkContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxSignData(
		pkContext.Handle, cSignAlgo, cData, cDataLength,
		cExternal, cAppendCert, &cSign, &cSignSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	sign := C.GoBytes(unsafe.Pointer(cSign), C.int(cSignSize))
	C.CtxFreeMemory(pkContext.Handle, cSign)

	return sign, makeError(cError, lang)
}

// CtxCreateSignerEx Creates information about the signer with
// additional verification information
func CtxCreateSignerEx(pkContext *PrivateKeyContext, signAlgo int, hash []byte, noContentTimeStamp bool, signType int) ([]byte, error) {
	cSignAlgo := C.ulong(signAlgo)
	cSignType := C.ulong(signType)
	cNoContentTimeStamp := toCBool(noContentTimeStamp)
	cHash, cHashLength := cbuf(hash)
	var cSignerInfo *C.uchar
	var cSignerInfoLength C.ulong

	cError := C.CtxCreateSignerEx(unsafe.Pointer(pkContext.Handle),
		cSignAlgo, cHash, cHashLength, cNoContentTimeStamp,
		cSignType, &cSignerInfo, &cSignerInfoLength)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	signerInfo := C.GoBytes(unsafe.Pointer(cSignerInfo), C.int(cSignerInfoLength))
	C.FreeMemory(cSignerInfo)

	return signerInfo, makeError(cError, lang)
}

// RawEnvelopData envelop data with raw algorithm
func RawEnvelopData(recipientCert []byte, data []byte) ([]byte, error) {
	cRecipientCert, cRecipientCertSize := cbuf(recipientCert)
	cData, cDataSize := cbuf(data)
	var cEnvelopedData *C.uchar
	var cEnvelopedDataSize C.ulong

	cError := C.RawEnvelopData(cRecipientCert, cRecipientCertSize,
		cData, cDataSize, &cEnvelopedData, &cEnvelopedDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	envelopedData := C.GoBytes(unsafe.Pointer(cEnvelopedData), C.int(cEnvelopedDataSize))
	C.FreeMemory(cEnvelopedData)

	return envelopedData, makeError(cError, lang)
}

// RawDevelopData develop data with raw algorithm
func RawDevelopData(envelopedData []byte) ([]byte, *SenderInfo, error) {
	cEnvelopedData, cEnvelopedDataSize := cbuf(envelopedData)
	var cData *C.uchar
	var cDataSize C.ulong
	var cSenderInfo **C.char
	var cSenderInfoSize C.ulong

	cError := C.RawDevelopData(cEnvelopedData, cEnvelopedDataSize,
		&cData, &cDataSize, &cSenderInfo, &cSenderInfoSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(cDataSize))
	C.FreeMemory(cData)

	senderInfo := decodeSenderInfo(cSenderInfo, cSenderInfoSize)
	C.FreeStructFields(cSenderInfo, cSenderInfoSize)

	return data, senderInfo, makeError(cError, lang)
}

// CtxEnvelopData envelopes data
func CtxEnvelopData(pkContext *PrivateKeyContext, clientsCerts [][]byte, clientAppendType int, signData bool, appendCert bool, data []byte) ([]byte, error) {
	cClientsData, cClientsDataSize := cbuf(data)
	cClientCertsCount, cClientCerts, cClientsCertsSizes := cbufs(clientsCerts)
	defer cbufsFree(cClientCertsCount, cClientCerts, cClientsCertsSizes)
	cClientAppendType := C.ulong(clientAppendType)
	cSignData := toCBool(signData)
	cAppendCert := toCBool(appendCert)
	var cEnvelopedData *C.uchar
	var cEnvelopedDataSize C.ulong

	if pkContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxEnvelopData(
		pkContext.Handle, cClientCertsCount,
		cClientCerts, cClientsCertsSizes,
		cClientAppendType, cSignData,
		cAppendCert, cClientsData, cClientsDataSize,
		&cEnvelopedData, &cEnvelopedDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	envelopedData := C.GoBytes(unsafe.Pointer(cEnvelopedData), C.int(cEnvelopedDataSize))
	C.CtxFreeMemory(pkContext.Handle, cEnvelopedData)

	return envelopedData, makeError(cError, lang)
}

// CtxDevelopData developes data
func CtxDevelopData(pkContext *PrivateKeyContext, envelopedData []byte, senderCert []byte) ([]byte, *SenderInfo, error) {
	cEnvelopedData, cEnvelopedDataSize := cbuf(envelopedData)
	cSenderCert, cSenderCertSize := cbuf(senderCert)
	var cData *C.uchar
	var cDataSize C.ulong
	var cSenderInfo **C.char
	var cSenderInfoSize C.ulong

	if pkContext == nil {
		return nil, nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxDevelopData(
		pkContext.Handle, nil, cEnvelopedData, cEnvelopedDataSize,
		cSenderCert, cSenderCertSize, &cData, &cDataSize,
		&cSenderInfo, &cSenderInfoSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(cDataSize))
	C.CtxFreeMemory(pkContext.Handle, cData)

	senderInfo := decodeSenderInfo(cSenderInfo, cSenderInfoSize)
	C.FreeStructFields(cSenderInfo, cSenderInfoSize)

	return data, senderInfo, makeError(cError, lang)
}

// SessionDestroy frees session context
func SessionDestroy(session *Session) error {
	if session == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.SessionDestroy(session.Handle)

	return makeError(cError, lang)
}

// SessionGetPeerCertificateInfo get peer certificate for session
func SessionGetPeerCertificateInfo(session *Session) (*CertInfo, error) {
	var cInfo **C.char
	var cInfoSize C.ulong

	if session == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.SessionGetPeerCertificateInfo(
		session.Handle, &cInfo, &cInfoSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	info := decodeCertInfo(cInfo, cInfoSize)
	C.FreeStructFields(cInfo, cInfoSize)

	return info, makeError(cError, lang)
}

// ClientRawMultiSessionCreate creates raw multi user session by client
func ClientRawMultiSessionCreate(expireTime int, serverData []byte) (*Session, error) {
	cExpireTime := C.ulong(expireTime)
	cServerData, cServerDataSize := cbuf(serverData)

	session := new(Session)

	cError := C.ClientRawMultiSessionCreate(
		cExpireTime, cServerData, cServerDataSize, &session.Handle)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	return session, makeError(cError, lang)
}

// ServerRawMultiSessionCreate creates raw multi user session by server
func ServerRawMultiSessionCreate(expireTime int, clientsCerts [][]byte) (*Session, []byte, error) {
	cExpireTime := C.ulong(expireTime)
	cClientCertsCount, cClientCerts, cClientsCertsSizes := cbufs(clientsCerts)
	defer cbufsFree(cClientCertsCount, cClientCerts, cClientsCertsSizes)
	var cClientsData *C.uchar
	var cClientsDataSize C.ulong

	session := new(Session)

	cError := C.ServerRawMultiSessionCreate(
		cExpireTime, cClientCertsCount, cClientCerts, cClientsCertsSizes,
		&cClientsData, &cClientsDataSize, &session.Handle)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	clientsData := C.GoBytes(unsafe.Pointer(cClientsData),
		C.int(cClientsDataSize))
	C.FreeMemory(cClientsData)

	return session, clientsData, makeError(cError, lang)
}

// RawMultiSessionAddClients creates new clients data for raw multi user session
func RawMultiSessionAddClients(session *Session, clientsCerts [][]byte) ([]byte, error) {
	cClientCertsCount, cClientCerts, cClientsCertsSizes := cbufs(clientsCerts)
	defer cbufsFree(cClientCertsCount, cClientCerts, cClientsCertsSizes)
	var cClientsData *C.uchar
	var cClientsDataSize C.ulong

	if session == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.RawMultiSessionAddClients(
		session.Handle, cClientCertsCount, cClientCerts, cClientsCertsSizes,
		&cClientsData, &cClientsDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	clientsData := C.GoBytes(unsafe.Pointer(cClientsData), C.int(cClientsDataSize))
	C.FreeMemory(cClientsData)

	return clientsData, makeError(cError, lang)
}

// SessionEncrypt encrypts data with session
func SessionEncrypt(session *Session, data []byte) ([]byte, error) {
	cData, cDataSize := cbuf(data)
	var cEncryptedData *C.uchar
	var cEncryptedDataSize C.ulong

	if session == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.SessionEncrypt(session.Handle,
		cData, cDataSize, &cEncryptedData, &cEncryptedDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	encryptedData := C.GoBytes(unsafe.Pointer(cEncryptedData), C.int(cEncryptedDataSize))
	C.FreeMemory(cEncryptedData)

	return encryptedData, makeError(cError, lang)
}

// SessionDecrypt decrypts data with session
func SessionDecrypt(session *Session, encryptedData []byte) ([]byte, error) {
	cEncryptedData, cEncryptedDataSize := cbuf(encryptedData)
	var cData *C.uchar
	var cDataSize C.ulong

	if session == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.SessionDecrypt(session.Handle,
		cEncryptedData, cEncryptedDataSize, &cData, &cDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(cDataSize))
	C.FreeMemory(cData)

	return data, makeError(cError, lang)
}

// CtxCreate creates context
func CtxCreate() (*Context, error) {
	ctx := new(Context)

	cError := C.CtxCreate(&ctx.Handle)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	return ctx, makeError(cError, lang)
}

// CtxFree frees context
func CtxFree(ctx *Context) error {
	if ctx == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.CtxFree(ctx.Handle)

	return makeError(cError, lang)
}

// AlgoCtxCreate creates algorithm context
func AlgoCtxCreate(algo int) (*AlgoContext, error) {
	cAlgo := C.ulong(algo)
	algoContext := new(AlgoContext)

	cError := C.AlgoCtxCreate(cAlgo, &algoContext.Handle)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	return algoContext, makeError(cError, lang)
}

// AlgoCtxGenerateKey generates algorithm key
func AlgoCtxGenerateKey(algoContext *AlgoContext) error {
	if algoContext == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxGenerateKey(algoContext.Handle)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// AlgoCtxSetKey sets algorithm key
func AlgoCtxSetKey(algoContext *AlgoContext, key []byte, iv []byte) error {
	cKey, cKeySize := cbuf(key)
	cIV, cIVSize := cbuf(iv)

	if algoContext == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxSetKey(algoContext.Handle,
		cKey, cKeySize, cIV, cIVSize)
	if cError != ErrorNone {
		return makeError(cError, lang)
	}

	return makeError(cError, lang)
}

// AlgoCtxGetKey gets algorithm key
func AlgoCtxGetKey(algoContext *AlgoContext) ([]byte, []byte, error) {
	var cKeySize C.ulong
	var cIVSize C.ulong

	if algoContext == nil {
		return nil, nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxGetKeySize(algoContext.Handle,
		&cKeySize, &cIVSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	cKey := C.malloc(C.size_t(cKeySize))
	defer C.free(unsafe.Pointer(cKey))
	cIV := C.malloc(C.size_t(cIVSize))
	defer C.free(unsafe.Pointer(cIV))

	cError = C.AlgoCtxGetKey(algoContext.Handle,
		(*C.uchar)(cKey), cKeySize, (*C.uchar)(cIV), cIVSize)
	if cError != ErrorNone {
		return nil, nil, makeError(cError, lang)
	}

	key := C.GoBytes(unsafe.Pointer(cKey), C.int(cKeySize))
	iv := C.GoBytes(unsafe.Pointer(cIV), C.int(cIVSize))

	return key, iv, makeError(cError, lang)
}

// AlgoCtxEncrypt encrypts data
func AlgoCtxEncrypt(algoContext *AlgoContext, data []byte) ([]byte, error) {
	cData, cDataSize := cbuf(data)

	if algoContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxEncrypt(algoContext.Handle,
		cData, cDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	encryptedData := C.GoBytes(unsafe.Pointer(cData), C.int(cDataSize))

	return encryptedData, makeError(cError, lang)
}

// AlgoCtxDecrypt decrypts data
func AlgoCtxDecrypt(algoContext *AlgoContext, encryptedData []byte) ([]byte, error) {
	cEncryptedData, cEncryptedDataSize := cbuf(encryptedData)

	if algoContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxDecrypt(algoContext.Handle,
		cEncryptedData, cEncryptedDataSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	data := C.GoBytes(unsafe.Pointer(cEncryptedData), C.int(cEncryptedDataSize))

	return data, makeError(cError, lang)
}

// AlgoCtxGetDataMAC gets data MAC
func AlgoCtxGetDataMAC(algoContext *AlgoContext, data []byte, macSize int) ([]byte, error) {
	cData, cDataSize := cbuf(data)
	cMacSize := C.ulong(macSize)

	if algoContext == nil {
		return nil, makeError(ErrorBadParameter, lang)
	}

	cMac := C.malloc(C.size_t(cMacSize))
	defer C.free(unsafe.Pointer(cMac))

	cError := C.AlgoCtxGetDataMAC(algoContext.Handle,
		cData, cDataSize, (*C.uchar)(cMac), cMacSize)
	if cError != ErrorNone {
		return nil, makeError(cError, lang)
	}

	mac := C.GoBytes(unsafe.Pointer(cMac), C.int(cMacSize))

	return mac, makeError(cError, lang)
}

// AlgoCtxFree frees algorithm context
func AlgoCtxFree(algoContext *AlgoContext) error {
	if algoContext == nil {
		return makeError(ErrorBadParameter, lang)
	}

	cError := C.AlgoCtxFree(algoContext.Handle)

	return makeError(cError, lang)
}
