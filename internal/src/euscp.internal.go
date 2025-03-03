// =============================================================================

// Package euscp with internal module functions
package src

// #include <stdlib.h>
// #include <string.h>
// #include "Module.h"
import (
	"C"
)
import (
	"encoding/base64"
	"strconv"
	"time"
	"unsafe"
)

// =============================================================================

const (
	FileStoreSettingsFieldsCount          = 8
	ProxySettingsFieldsCount              = 7
	OCSPSettingsFieldsCount               = 4
	TSPSettingsFieldsCount                = 3
	LDAPSettingsFieldsCount               = 6
	CMPSettingsFieldsCount                = 4
	OCSPAccessInfoModeSettingsFieldsCount = 1
	OCSPAccessInfoSettingsFieldsCount     = 3
	KeyMediaFieldsCount                   = 3
	LogSettingsFieldsCount                = 5
	ModeSettingsFieldsCount               = 1
	UserInfoFieldsCount                   = 23
)

const (
	TimeFormat = "02.01.2006 15:04:05"
)

const ErrorMessageMaxLength = 1025

const UserInfoVersion = 3

// =============================================================================

func cbuf(buf []byte) (
	ptr *C.uchar, size C.ulong) {
	if buf == nil {
		return nil, 0
	}

	var bufptr *byte
	if cap(buf) > 0 {
		bufptr = &(buf[:1][0])
	}
	return (*C.uchar)(bufptr), C.ulong(len(buf))
}

// -----------------------------------------------------------------------------

func cbufs(bufs [][]byte) (
	cSize C.ulong, cBytesArrays **C.uchar, cBytesArraysSizes *C.ulong) {
	cSize = C.ulong(len(bufs))
	cBytesArrays = (**C.uchar)(C.malloc(
		C.size_t(unsafe.Sizeof(*cBytesArrays)) * C.size_t(cSize)))
	cBytesArraysSizes = (*C.ulong)(C.malloc(
		C.size_t(unsafe.Sizeof(cBytesArraysSizes)) * C.size_t(cSize)))

	arrays := (*[1 << 28]*C.uchar)(unsafe.Pointer(
		cBytesArrays))[:cSize:cSize]
	arraysSizes := (*[1 << 28]C.ulong)(unsafe.Pointer(
		cBytesArraysSizes))[:cSize:cSize]

	for i, buf := range bufs {
		arrays[i] = (*C.uchar)(C.CBytes(buf))
		arraysSizes[i] = C.ulong(len(buf))
	}

	return cSize, cBytesArrays, cBytesArraysSizes
}

// -----------------------------------------------------------------------------

func gobufs(cSize C.ulong,
	cBytesArrays **C.uchar, cBytesArraysSizes *C.ulong) (
	bufs [][]byte) {
	if cBytesArrays != nil && cBytesArraysSizes != nil {
		arrays := (*[1 << 28]*C.uchar)(unsafe.Pointer(
			cBytesArrays))[:cSize:cSize]
		sizes := (*[1 << 28]C.ulong)(unsafe.Pointer(
			cBytesArraysSizes))[:cSize:cSize]
		for i := 0; i < len(arrays); i++ {
			buf := C.GoBytes(
				unsafe.Pointer(arrays[i]), C.int(sizes[i]))
			bufs = append(bufs, buf)
		}
	}

	return bufs
}

// -----------------------------------------------------------------------------

func cbufsFree(cSize C.ulong,
	cBytesArrays **C.uchar, cBytesArraysSizes *C.ulong) {
	if cBytesArrays != nil {
		arrays := (*[1 << 28]*C.uchar)(unsafe.Pointer(
			cBytesArrays))[:cSize:cSize]
		for i := 0; i < len(arrays); i++ {
			C.free(unsafe.Pointer(arrays[i]))
		}
		C.free(unsafe.Pointer(cBytesArrays))
	}

	if cBytesArraysSizes != nil {
		C.free(unsafe.Pointer(cBytesArraysSizes))
	}
}

// -----------------------------------------------------------------------------

func cStrings(strings []string) (
	cStrings **C.char, cSize C.ulong) {
	length := len(strings)
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cStrings)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cStrings))[:length:length]

	for i := 0; i < length; i++ {
		setFieldString(strings[i], fields, &index)
	}

	return cStrings, C.ulong(length)
}

// -----------------------------------------------------------------------------

func toCBool(val bool) (
	cVal C.int) {
	cVal = C.int(0)
	if val {
		cVal = 1
	}
	return cVal
}

// =============================================================================

func getFieldString(cFields []*C.char, index *int) (
	str string) {
	str = C.GoString(cFields[*index])
	*index = *index + 1

	return str
}

// -----------------------------------------------------------------------------

func setFieldString(val string, cFields []*C.char, index *int) {
	cStr := C.CString(val)
	cFields[*index] = cStr
	*index = *index + 1
}

// -----------------------------------------------------------------------------

func getFieldBytes(cFields []*C.char, index *int) (
	bytes []byte) {
	str := getFieldString(cFields, index)
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		bytes = nil
	}
	return bytes
}

// -----------------------------------------------------------------------------

func getFieldInt(cFields []*C.char, index *int) (
	val int) {
	str := getFieldString(cFields, index)
	val, err := strconv.Atoi(str)
	if err != nil {
		val = 0
	}
	return val
}

// -----------------------------------------------------------------------------

func setFieldInt(val int, cFields []*C.char, index *int) {
	setFieldString(strconv.Itoa(val), cFields, index)
}

// -----------------------------------------------------------------------------

func getFieldBool(cFields []*C.char, index *int) (
	val bool) {
	return getFieldInt(cFields, index) != 0
}

// -----------------------------------------------------------------------------

func setFieldBool(val bool, cFields []*C.char, index *int) {
	intVal := 0
	if val {
		intVal = 1
	}

	setFieldInt(intVal, cFields, index)
}

// -----------------------------------------------------------------------------

func getFieldTime(cFields []*C.char, index *int) (
	date time.Time) {
	str := getFieldString(cFields, index)
	date, error := time.Parse(TimeFormat, str)
	if error != nil {
		return time.Unix(0, 0)
	}
	return date
}

// -----------------------------------------------------------------------------

func setFieldTime(val time.Time, cFields []*C.char, index *int) {
	setFieldString(val.Format(TimeFormat), cFields, index)
}

// -----------------------------------------------------------------------------

func encodeFileStoreSettings(settings *FileStoreSettings) (
	cFields **C.char, cLength C.ulong) {
	length := FileStoreSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldString(settings.Path, fields, &index)
	setFieldBool(settings.CheckCRLs, fields, &index)
	setFieldBool(settings.AutoRefresh, fields, &index)
	setFieldBool(settings.OwnCRLsOnly, fields, &index)
	setFieldBool(settings.FullAndDeltaCRLs, fields, &index)
	setFieldBool(settings.AutoDownloadCRLs, fields, &index)
	setFieldBool(settings.SaveLoadedCerts, fields, &index)
	setFieldInt(settings.ExpireTime, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeFileStoreSettings(cFields **C.char, cLength C.ulong) (
	settings *FileStoreSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(FileStoreSettings)

	settings.Path = getFieldString(fields, &index)
	settings.CheckCRLs = getFieldBool(fields, &index)
	settings.AutoRefresh = getFieldBool(fields, &index)
	settings.OwnCRLsOnly = getFieldBool(fields, &index)
	settings.FullAndDeltaCRLs = getFieldBool(fields, &index)
	settings.AutoDownloadCRLs = getFieldBool(fields, &index)
	settings.SaveLoadedCerts = getFieldBool(fields, &index)
	settings.ExpireTime = getFieldInt(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeProxySettings(settings *ProxySettings) (
	cFields **C.char, cLength C.ulong) {
	length := ProxySettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Use, fields, &index)
	setFieldBool(settings.Anonymus, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)
	setFieldString(settings.User, fields, &index)
	setFieldString(settings.Password, fields, &index)
	setFieldBool(settings.SavePassword, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeProxySettings(cFields **C.char, cLength C.ulong) (
	settings *ProxySettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(ProxySettings)

	settings.Use = getFieldBool(fields, &index)
	settings.Anonymus = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)
	settings.User = getFieldString(fields, &index)
	settings.Password = getFieldString(fields, &index)
	settings.SavePassword = getFieldBool(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeOCSPSettings(settings *OCSPSettings) (
	cFields **C.char, cLength C.ulong) {
	length := OCSPSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Use, fields, &index)
	setFieldBool(settings.BeforeStore, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeOCSPSettings(cFields **C.char, cLength C.ulong) (
	settings *OCSPSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(OCSPSettings)

	settings.Use = getFieldBool(fields, &index)
	settings.BeforeStore = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeOCSPAccessInfoModeSettings(settings *OCSPAccessInfoModeSettings) (
	cFields **C.char, cLength C.ulong) {
	length := OCSPAccessInfoModeSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Enabled, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeOCSPAccessInfoModeSettings(cFields **C.char, cLength C.ulong) (
	settings *OCSPAccessInfoModeSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(OCSPAccessInfoModeSettings)

	settings.Enabled = getFieldBool(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeOCSPAccessInfoSettings(settings *OCSPAccessInfoSettings) (
	cFields **C.char, cLength C.ulong) {
	length := OCSPAccessInfoSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldString(settings.IssuerCN, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeOCSPAccessInfoSettings(cFields **C.char, cLength C.ulong) (
	settings *OCSPAccessInfoSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(OCSPAccessInfoSettings)

	settings.IssuerCN = getFieldString(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeTSPSettings(settings *TSPSettings) (
	cFields **C.char, cLength C.ulong) {
	length := TSPSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.GetStamps, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeTSPSettings(cFields **C.char, cLength C.ulong) (
	settings *TSPSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(TSPSettings)

	settings.GetStamps = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeLDAPSettings(settings *LDAPSettings) (
	cFields **C.char, cLength C.ulong) {
	length := LDAPSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Use, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)
	setFieldBool(settings.Anonymus, fields, &index)
	setFieldString(settings.User, fields, &index)
	setFieldString(settings.Password, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeLDAPSettings(cFields **C.char, cLength C.ulong) (
	settings *LDAPSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(LDAPSettings)

	settings.Use = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)
	settings.Anonymus = getFieldBool(fields, &index)
	settings.User = getFieldString(fields, &index)
	settings.Password = getFieldString(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeCMPSettings(settings *CMPSettings) (
	cFields **C.char, cLength C.ulong) {
	length := CMPSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Use, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)
	setFieldString(settings.CommonName, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeCMPSettings(cFields **C.char, cLength C.ulong) (
	settings *CMPSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(CMPSettings)

	settings.Use = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)
	settings.CommonName = getFieldString(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeLogSettings(settings *LogSettings) (
	cFields **C.char, cLength C.ulong) {
	length := LogSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.System, fields, &index)
	setFieldBool(settings.UseReportAgent, fields, &index)
	setFieldString(settings.Address, fields, &index)
	setFieldString(settings.Port, fields, &index)
	setFieldBool(settings.OnlyErrors, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeLogSettings(cFields **C.char, cLength C.ulong) (
	settings *LogSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(LogSettings)

	settings.System = getFieldBool(fields, &index)
	settings.UseReportAgent = getFieldBool(fields, &index)
	settings.Address = getFieldString(fields, &index)
	settings.Port = getFieldString(fields, &index)
	settings.OnlyErrors = getFieldBool(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeModeSettings(settings *ModeSettings) (
	cFields **C.char, cLength C.ulong) {
	length := ModeSettingsFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldBool(settings.Offline, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeModeSettings(cFields **C.char, cLength C.ulong) (
	settings *ModeSettings) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	settings = new(ModeSettings)

	settings.Offline = getFieldBool(fields, &index)

	return settings
}

// -----------------------------------------------------------------------------

func encodeKeyMedia(keyMedia *KeyMedia) (
	cFields **C.char, cLength C.ulong) {
	length := KeyMediaFieldsCount
	index := 0

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldInt(keyMedia.TypeIndex, fields, &index)
	setFieldInt(keyMedia.DeviceIndex, fields, &index)
	setFieldString(keyMedia.Password, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeCertOwnerInfo(cFields **C.char, cLength C.ulong) (
	info *CertOwnerInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(CertOwnerInfo)

	info.IsFilled = getFieldBool(fields, &index)
	info.Issuer = getFieldString(fields, &index)
	info.IssuerCN = getFieldString(fields, &index)
	info.Serial = getFieldString(fields, &index)
	info.Subject = getFieldString(fields, &index)
	info.SubjCN = getFieldString(fields, &index)
	info.SubjOrg = getFieldString(fields, &index)
	info.SubjOrgUnit = getFieldString(fields, &index)
	info.SubjTitle = getFieldString(fields, &index)
	info.SubjState = getFieldString(fields, &index)
	info.SubjLocality = getFieldString(fields, &index)
	info.SubjFullName = getFieldString(fields, &index)
	info.SubjAddress = getFieldString(fields, &index)
	info.SubjPhone = getFieldString(fields, &index)
	info.SubjEMail = getFieldString(fields, &index)
	info.SubjDNS = getFieldString(fields, &index)
	info.SubjEDRPOUCode = getFieldString(fields, &index)
	info.SubjDRFOCode = getFieldString(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func decodeSignerInfo(cFields **C.char, cLength C.ulong) (
	info *SignerInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(SignerInfo)

	info.IsFilled = getFieldBool(fields, &index)
	info.Issuer = getFieldString(fields, &index)
	info.IssuerCN = getFieldString(fields, &index)
	info.Serial = getFieldString(fields, &index)
	info.Subject = getFieldString(fields, &index)
	info.SubjCN = getFieldString(fields, &index)
	info.SubjOrg = getFieldString(fields, &index)
	info.SubjOrgUnit = getFieldString(fields, &index)
	info.SubjTitle = getFieldString(fields, &index)
	info.SubjState = getFieldString(fields, &index)
	info.SubjLocality = getFieldString(fields, &index)
	info.SubjFullName = getFieldString(fields, &index)
	info.SubjAddress = getFieldString(fields, &index)
	info.SubjPhone = getFieldString(fields, &index)
	info.SubjEMail = getFieldString(fields, &index)
	info.SubjDNS = getFieldString(fields, &index)
	info.SubjEDRPOUCode = getFieldString(fields, &index)
	info.SubjDRFOCode = getFieldString(fields, &index)
	info.IsTimeAvail = getFieldBool(fields, &index)
	info.IsTimeStamp = getFieldBool(fields, &index)
	info.Time = getFieldTime(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func decodeSenderInfo(cFields **C.char, cLength C.ulong) (
	info *SenderInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(SenderInfo)

	info.IsFilled = getFieldBool(fields, &index)
	info.Issuer = getFieldString(fields, &index)
	info.IssuerCN = getFieldString(fields, &index)
	info.Serial = getFieldString(fields, &index)
	info.Subject = getFieldString(fields, &index)
	info.SubjCN = getFieldString(fields, &index)
	info.SubjOrg = getFieldString(fields, &index)
	info.SubjOrgUnit = getFieldString(fields, &index)
	info.SubjTitle = getFieldString(fields, &index)
	info.SubjState = getFieldString(fields, &index)
	info.SubjLocality = getFieldString(fields, &index)
	info.SubjFullName = getFieldString(fields, &index)
	info.SubjAddress = getFieldString(fields, &index)
	info.SubjPhone = getFieldString(fields, &index)
	info.SubjEMail = getFieldString(fields, &index)
	info.SubjDNS = getFieldString(fields, &index)
	info.SubjEDRPOUCode = getFieldString(fields, &index)
	info.SubjDRFOCode = getFieldString(fields, &index)
	info.IsTimeAvail = getFieldBool(fields, &index)
	info.IsTimeStamp = getFieldBool(fields, &index)
	info.Time = getFieldTime(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func decodeTimeInfo(cFields **C.char, cLength C.ulong) (
	info *TimeInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(TimeInfo)

	info.Version = getFieldInt(fields, &index)
	info.IsTimeAvail = getFieldBool(fields, &index)
	info.IsTimeStamp = getFieldBool(fields, &index)
	info.Time = getFieldTime(fields, &index)
	info.IsSignTimeStampAvail = getFieldBool(fields, &index)
	info.SignTimeStamp = getFieldTime(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func decodeCertInfo(cFields **C.char, cLength C.ulong) (
	info *CertInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(CertInfo)

	info.IsFilled = getFieldBool(fields, &index)
	info.Version = getFieldInt(fields, &index)
	info.Issuer = getFieldString(fields, &index)
	info.IssuerCN = getFieldString(fields, &index)
	info.Serial = getFieldString(fields, &index)
	info.Subject = getFieldString(fields, &index)
	info.SubjCN = getFieldString(fields, &index)
	info.SubjOrg = getFieldString(fields, &index)
	info.SubjOrgUnit = getFieldString(fields, &index)
	info.SubjTitle = getFieldString(fields, &index)
	info.SubjState = getFieldString(fields, &index)
	info.SubjLocality = getFieldString(fields, &index)
	info.SubjFullName = getFieldString(fields, &index)
	info.SubjAddress = getFieldString(fields, &index)
	info.SubjPhone = getFieldString(fields, &index)
	info.SubjEMail = getFieldString(fields, &index)
	info.SubjDNS = getFieldString(fields, &index)
	info.SubjEDRPOUCode = getFieldString(fields, &index)
	info.SubjDRFOCode = getFieldString(fields, &index)
	info.SubjNBUCode = getFieldString(fields, &index)
	info.SubjSPFMCode = getFieldString(fields, &index)
	info.SubjOCode = getFieldString(fields, &index)
	info.SubjOUCode = getFieldString(fields, &index)
	info.SubjUserCode = getFieldString(fields, &index)
	info.CertBeginTime = getFieldTime(fields, &index)
	info.CertEndTime = getFieldTime(fields, &index)
	info.IsPrivKeyTimesAvail = getFieldBool(fields, &index)
	info.PrivKeyBeginTime = getFieldTime(fields, &index)
	info.PrivKeyEndTime = getFieldTime(fields, &index)
	info.PublicKeyBits = getFieldInt(fields, &index)
	info.PublicKey = getFieldString(fields, &index)
	info.PublicKeyID = getFieldString(fields, &index)
	info.IsECDHPublicKey = getFieldBool(fields, &index)
	info.ECDHPublicKeyBits = getFieldInt(fields, &index)
	info.ECDHPublicKey = getFieldString(fields, &index)
	info.ECDHPublicKeyID = getFieldString(fields, &index)
	info.IssuerPublicKeyID = getFieldString(fields, &index)
	info.KeyUsage = getFieldString(fields, &index)
	info.ExtKeyUsages = getFieldString(fields, &index)
	info.Policies = getFieldString(fields, &index)
	info.CRLDistribPoint1 = getFieldString(fields, &index)
	info.CRLDistribPoint2 = getFieldString(fields, &index)
	info.IsPowerCert = getFieldBool(fields, &index)
	info.IsSubjTypeAvail = getFieldBool(fields, &index)
	info.IsSubjCA = getFieldBool(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func decodeCertInfoEx(cFields **C.char, cLength C.ulong) (
	info *CertInfoEx) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	info = new(CertInfoEx)

	info.IsFilled = getFieldBool(fields, &index)
	info.Version = getFieldInt(fields, &index)
	info.Issuer = getFieldString(fields, &index)
	info.IssuerCN = getFieldString(fields, &index)
	info.Serial = getFieldString(fields, &index)
	info.Subject = getFieldString(fields, &index)
	info.SubjCN = getFieldString(fields, &index)
	info.SubjOrg = getFieldString(fields, &index)
	info.SubjOrgUnit = getFieldString(fields, &index)
	info.SubjTitle = getFieldString(fields, &index)
	info.SubjState = getFieldString(fields, &index)
	info.SubjLocality = getFieldString(fields, &index)
	info.SubjFullName = getFieldString(fields, &index)
	info.SubjAddress = getFieldString(fields, &index)
	info.SubjPhone = getFieldString(fields, &index)
	info.SubjEMail = getFieldString(fields, &index)
	info.SubjDNS = getFieldString(fields, &index)
	info.SubjEDRPOUCode = getFieldString(fields, &index)
	info.SubjDRFOCode = getFieldString(fields, &index)
	info.SubjNBUCode = getFieldString(fields, &index)
	info.SubjSPFMCode = getFieldString(fields, &index)
	info.SubjOCode = getFieldString(fields, &index)
	info.SubjOUCode = getFieldString(fields, &index)
	info.SubjUserCode = getFieldString(fields, &index)
	info.CertBeginTime = getFieldTime(fields, &index)
	info.CertEndTime = getFieldTime(fields, &index)
	info.IsPrivKeyTimesAvail = getFieldBool(fields, &index)
	info.PrivKeyBeginTime = getFieldTime(fields, &index)
	info.PrivKeyEndTime = getFieldTime(fields, &index)
	info.PublicKeyBits = getFieldInt(fields, &index)
	info.PublicKey = getFieldString(fields, &index)
	info.PublicKeyID = getFieldString(fields, &index)
	info.IssuerPublicKeyID = getFieldString(fields, &index)
	info.KeyUsage = getFieldString(fields, &index)
	info.ExtKeyUsages = getFieldString(fields, &index)
	info.Policies = getFieldString(fields, &index)
	info.CRLDistribPoint1 = getFieldString(fields, &index)
	info.CRLDistribPoint2 = getFieldString(fields, &index)
	info.IsPowerCert = getFieldBool(fields, &index)
	info.IsSubjTypeAvail = getFieldBool(fields, &index)
	info.IsSubjCA = getFieldBool(fields, &index)
	info.ChainLength = getFieldInt(fields, &index)
	info.UPN = getFieldString(fields, &index)
	info.PublicKeyType = getFieldInt(fields, &index)
	info.KeyUsageType = getFieldInt(fields, &index)
	info.RSAModul = getFieldString(fields, &index)
	info.RSAExponent = getFieldString(fields, &index)
	info.OCSPAccessInfo = getFieldString(fields, &index)
	info.IssuerAccessInfo = getFieldString(fields, &index)
	info.TSPAccessInfo = getFieldString(fields, &index)
	info.IsLimitValueAvailable = getFieldBool(fields, &index)
	info.LimitValue = getFieldInt(fields, &index)
	info.LimitValueCurrency = getFieldString(fields, &index)
	info.SubjType = getFieldInt(fields, &index)
	info.SubjSubType = getFieldInt(fields, &index)
	info.SubjUNZR = getFieldString(fields, &index)
	info.SubjCountry = getFieldString(fields, &index)
	info.Fingerprint = getFieldString(fields, &index)
	info.IsQSCD = getFieldBool(fields, &index)
	info.SubjUserID = getFieldString(fields, &index)
	info.CertHashType = getFieldInt(fields, &index)

	return info
}

// -----------------------------------------------------------------------------

func encodeUserInfo(userInfo *UserInfo) (
	cFields **C.char, cLength C.ulong) {
	length := UserInfoFieldsCount
	index := 0

	if userInfo == nil {
		return nil, 0
	}

	cError := C.AllocStructFields(C.ulong(length), &cFields)
	if cError != ErrorNone {
		return nil, 0
	}
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]

	setFieldInt(UserInfoVersion, fields, &index)
	setFieldString(userInfo.CommonName, fields, &index)
	setFieldString(userInfo.Locality, fields, &index)
	setFieldString(userInfo.State, fields, &index)
	setFieldString(userInfo.Organization, fields, &index)
	setFieldString(userInfo.OrgUnit, fields, &index)
	setFieldString(userInfo.Title, fields, &index)
	setFieldString(userInfo.Street, fields, &index)
	setFieldString(userInfo.Phone, fields, &index)
	setFieldString(userInfo.Surname, fields, &index)
	setFieldString(userInfo.Givenname, fields, &index)
	setFieldString(userInfo.EMail, fields, &index)
	setFieldString(userInfo.DNS, fields, &index)
	setFieldString(userInfo.EDRPOUCode, fields, &index)
	setFieldString(userInfo.DRFOCode, fields, &index)
	setFieldString(userInfo.NBUCode, fields, &index)
	setFieldString(userInfo.SPFMCode, fields, &index)
	setFieldString(userInfo.OCode, fields, &index)
	setFieldString(userInfo.OUCode, fields, &index)
	setFieldString(userInfo.UserCode, fields, &index)
	setFieldString(userInfo.UPN, fields, &index)
	setFieldString(userInfo.UNZR, fields, &index)
	setFieldString(userInfo.Country, fields, &index)

	return cFields, C.ulong(length)
}

// -----------------------------------------------------------------------------

func decodeRequestInfo(cFields **C.char, cLength C.ulong) (
	request *RequestInfo) {
	length := int(cLength)
	fields := (*[1 << 28]*C.char)(unsafe.Pointer(cFields))[:length:length]
	index := 0
	request = new(RequestInfo)

	request.Type = getFieldInt(fields, &index)
	request.Request = getFieldBytes(fields, &index)
	request.FileName = getFieldString(fields, &index)
	request.IsFilled = getFieldBool(fields, &index)
	request.Version = getFieldInt(fields, &index)
	request.IsSimple = getFieldBool(fields, &index)
	request.Subject = getFieldString(fields, &index)
	request.SubjCN = getFieldString(fields, &index)
	request.SubjOrg = getFieldString(fields, &index)
	request.SubjOrgUnit = getFieldString(fields, &index)
	request.SubjTitle = getFieldString(fields, &index)
	request.SubjState = getFieldString(fields, &index)
	request.SubjLocality = getFieldString(fields, &index)
	request.SubjFullName = getFieldString(fields, &index)
	request.SubjAddress = getFieldString(fields, &index)
	request.SubjPhone = getFieldString(fields, &index)
	request.SubjEMail = getFieldString(fields, &index)
	request.SubjDNS = getFieldString(fields, &index)
	request.SubjEDRPOUCode = getFieldString(fields, &index)
	request.SubjDRFOCode = getFieldString(fields, &index)
	request.SubjNBUCode = getFieldString(fields, &index)
	request.SubjSPFMCode = getFieldString(fields, &index)
	request.SubjOCode = getFieldString(fields, &index)
	request.SubjOUCode = getFieldString(fields, &index)
	request.SubjUserCode = getFieldString(fields, &index)
	request.IsCertTimesAvail = getFieldBool(fields, &index)
	request.CertBeginTime = getFieldTime(fields, &index)
	request.CertEndTime = getFieldTime(fields, &index)
	request.IsPrivKeyTimesAvail = getFieldBool(fields, &index)
	request.PrivKeyBeginTime = getFieldTime(fields, &index)
	request.PrivKeyEndTime = getFieldTime(fields, &index)
	request.PublicKeyType = getFieldInt(fields, &index)
	request.PublicKeyBits = getFieldInt(fields, &index)
	request.PublicKey = getFieldString(fields, &index)
	request.RSAModul = getFieldString(fields, &index)
	request.RSAExponent = getFieldString(fields, &index)
	request.PublicKeyID = getFieldString(fields, &index)
	request.ExtKeyUsages = getFieldString(fields, &index)
	request.CRLDistribPoint1 = getFieldString(fields, &index)
	request.CRLDistribPoint2 = getFieldString(fields, &index)
	request.IsSubjTypeAvail = getFieldBool(fields, &index)
	request.SubjType = getFieldInt(fields, &index)
	request.SubjSubType = getFieldInt(fields, &index)
	request.IsSelfSigned = getFieldBool(fields, &index)
	request.SignIssuer = getFieldString(fields, &index)
	request.SignSerial = getFieldString(fields, &index)
	request.SubjUNZR = getFieldString(fields, &index)
	request.SubjCountry = getFieldString(fields, &index)
	request.IsQSCD = getFieldBool(fields, &index)

	return request
}

// =============================================================================

func makeError(code C.ulong, lang int) (
	err Error) {
	szMessage := C.malloc(C.sizeof_char * ErrorMessageMaxLength)
	defer C.free(unsafe.Pointer(szMessage))

	C.GetErrorLangDesc(
		code,
		C.ulong(lang),
		(*C.char)(szMessage),
	)
	return Error{
		Code:    int(code),
		Message: C.GoString((*C.char)(szMessage)),
	}
}

// -----------------------------------------------------------------------------

func freeMemory(cPtr *C.uchar) {
	C.FreeMemory(cPtr)
}

// -----------------------------------------------------------------------------

func freeStructFields(cPtr **C.char, cLength C.ulong) {
	C.FreeStructFields(cPtr, cLength)
}

// =============================================================================
