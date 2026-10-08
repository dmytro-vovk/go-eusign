package euscp

import (
	"strconv"
	"time"
	"unsafe"

	"C"
)

const (
	ErrorNone                   = 0x0000
	ErrorUnknown                = 0xffff
	ErrorNotSupported           = 0xfffe
	ErrorNotInitialized         = 0x0001
	ErrorBadParameter           = 0x0002
	ErrorLibraryLoad            = 0x0003
	ErrorReadSettings           = 0x0004
	ErrorTransmitRequest        = 0x0005
	ErrorMemoryAllocation       = 0x0006
	WarningEndOfEnum            = 0x0007
	ErrorProxyNotAuthorized     = 0x0008
	ErrorNoGuiDialogs           = 0x0009
	ErrorDownloadFile           = 0x000a
	ErrorWriteSettings          = 0x000b
	ErrorCanceledByGui          = 0x000c
	ErrorOfflineMode            = 0x000d
	ErrorKeyMediasFailed        = 0x0011
	ErrorKeyMediasAccessFailed  = 0x0012
	ErrorKeyMediasReadFailed    = 0x0013
	ErrorKeyMediasWriteFailed   = 0x0014
	WarningKeyMediasReadOnly    = 0x0015
	ErrorKeyMediasDelete        = 0x0016
	ErrorKeyMediasClear         = 0x0017
	ErrorBadPrivateKey          = 0x0018
	ErrorPkiFormatsFailed       = 0x0021
	ErrorCspFailed              = 0x0022
	ErrorBadSignature           = 0x0023
	ErrorAuthFailed             = 0x0024
	ErrorNotReceiver            = 0x0025
	ErrorStorageFailed          = 0x0031
	ErrorBadCert                = 0x0032
	ErrorCertNotFound           = 0x0033
	ErrorInvalidCertTime        = 0x0034
	ErrorCertInCrl              = 0x0035
	ErrorBadCrl                 = 0x0036
	ErrorNoValidCrls            = 0x0037
	ErrorGetTimeStamp           = 0x0041
	ErrorBadTspResponse         = 0x0042
	ErrorTspServerCertNotFound  = 0x0043
	ErrorTspServerCertInvalid   = 0x0044
	ErrorGetOcspStatus          = 0x0051
	ErrorBadOcspResponse        = 0x0052
	ErrorCertBadByOcsp          = 0x0053
	ErrorOcspServerCertNotFound = 0x0054
	ErrorOcspServerCertInvalid  = 0x0055
	ErrorLdapError              = 0x0061
)

// Hash algorithms
const (
	CtxHashAlgoUnknown   = 0
	CtxHashAlgoGOST34311 = 1
	CtxHashAlgoSHA160    = 2
	CtxHashAlgoSHA224    = 3
	CtxHashAlgoSHA256    = 4
	CtxHashAlgoSHA384    = 5
	CtxHashAlgoSHA512    = 6
	CtxHashAlgoDSTU256   = 7
	CtxHashAlgoDSTU384   = 8
	CtxHashAlgoDSTU512   = 9
)

// Sign algorithms
const (
	CtxSignUnknown               = 0
	CtxSignDSTU4145WithGOST34311 = 1
	CtxSignRSAWithSHA            = 2
	CtxSignECDSAWithSHA          = 3
	CtxSignDSTU4145WithDSTU7564  = 4
)

// Parameters
const (
	ResolveOIDsOIDSParameter    = "ResolveOIDs"
	SaveSettingsParameter       = "SaveSettings"
	SignType                    = "SignType"
	ConnectionsTimeoutParameter = "ConnectionsTimeout"
)

// General settings
const (
	SettingsIDNone = 0x000
	SettingsIDAll  = 0xFFF
)

// Certificate subject types
const (
	SubjectTypeUndifferenced   = 0
	SubjectTypeCA              = 1
	SubjectTypeCAServer        = 2
	SubjectTypeRAAdministrator = 3
	SubjectTypeEndUser         = 4
)

// Certificate CA servers subject sub types
const (
	SubjectCAServerSubTypeUndifferenced = 0
	SubjectCAServerSubTypeCMP           = 1
	SubjectCAServerSubTypeTSP           = 2
	SubjectCAServerSubTypeOCSP          = 3
)

// Certificate key type
const (
	CertKeyTypeUnknown  = 0
	CertKeyTypeDSTU4145 = 1
	CertKeyTypeRSA      = 2
	CertKeyTypeECDSA    = 4
)

// Certificate hash type type
const (
	CertHashTypeUnknown   = 0
	CertHashTypeGOST34311 = 1
	CertHashTypeSHA1      = 2
	CertHashTypeSHA224    = 3
	CertHashTypeSHA256    = 4
	CertHashTypeSHA384    = 5
	CertHashTypeSHA512    = 6
	CertHashTypeDSTU256   = 7
	CertHashTypeDSTU384   = 8
	CertHashTypeDSTU512   = 9
)

// Key usage
const (
	KeyUsageUnknown          = 0x0000
	KeyUsageDigitalSignature = 0x0001
	KeyUsageNonRepudation    = 0x0002
	KeyUsageKeyAgreement     = 0x0010
)

// Sign types
const (
	SignTypeUnknown              = 0
	SignTypeCAdES_BES            = 1
	SignTypeCAdES_T              = 4
	SignTypeCAdES_C              = 8
	SignTypeCAdES_X_Long         = 16
	SignTypeCAdES_X_Long_Trusted = 128
)

// Keys types
const (
	KeysTypeNone                 = 0
	KeysTypeDSTUAndECDHWithGOSTS = 1
	KeysTypeRSAWithSHA           = 2
	KeysTypeECDSAWithSHA         = 4
	KeysTypeDSTUAndECDHWithDSTU  = 8
)

// Keys length
const (
	KeysLengthDS_UA_191  = 1
	KeysLengthDS_UA_257  = 2
	KeysLengthDS_UA_307  = 3
	KeysLengthDS_UA_File = 4
	KeysLengthDS_UA_Cert = 5

	KeysLengthKEP_UA_257  = 1
	KeysLengthKEP_UA_431  = 2
	KeysLengthKEP_UA_571  = 3
	KeysLengthKEP_UA_File = 4
	KeysLengthKEP_UA_Cert = 5

	KeysLengthDS_RSA_1024 = 1
	KeysLengthDS_RSA_2048 = 2
	KeysLengthDS_RSA_3072 = 3
	KeysLengthDS_RSA_4096 = 4
	KeysLengthDS_RSA_File = 5
	KeysLengthDS_RSA_Cert = 6

	KeysLengthDS_ECDSA_192  = 1
	KeysLengthDS_ECDSA_256  = 2
	KeysLengthDS_ECDSA_384  = 3
	KeysLengthDS_ECDSA_521  = 4
	KeysLengthDS_ECDSA_File = 5
	KeysLengthDS_ECDSA_Cert = 6
)

// Request types
const (
	RequestTypeUA_DS  = 1
	RequestTypeUA_KEP = 2
	RequestTypeRSA    = 3
	RequestTypeECDSA  = 4
)

// Recipient settings
const (
	RecipientAppendTypeByIssuerSerial = 1
	RecipientAppendTypeByKeyID        = 2
)

// Algorithms
const (
	AlgoDSTU7624_CFB_256 = 1
)

// DSTU7624 MAC size
const (
	AlgoDSTU7624_MAC_64  = 8
	AlgoDSTU7624_MAC_128 = 16
	AlgoDSTU7624_MAC_256 = 32
)

// Languages
const (
	LangDefault = 0
	LangUA      = 1
	LangRU      = 2
	LangEN      = 3
)

type Error struct {
	Code    int
	Message string
}

func (e Error) Error() string {
	return e.Message + " (" + strconv.Itoa(e.Code) + ")"
}

type SignerInfo struct {
	IsFilled       bool
	Issuer         string
	IssuerCN       string
	Serial         string
	Subject        string
	SubjCN         string
	SubjOrg        string
	SubjOrgUnit    string
	SubjTitle      string
	SubjState      string
	SubjLocality   string
	SubjFullName   string
	SubjAddress    string
	SubjPhone      string
	SubjEMail      string
	SubjDNS        string
	SubjEDRPOUCode string
	SubjDRFOCode   string
	IsTimeAvail    bool
	IsTimeStamp    bool
	Time           time.Time
}

type SenderInfo struct {
	IsFilled       bool
	Issuer         string
	IssuerCN       string
	Serial         string
	Subject        string
	SubjCN         string
	SubjOrg        string
	SubjOrgUnit    string
	SubjTitle      string
	SubjState      string
	SubjLocality   string
	SubjFullName   string
	SubjAddress    string
	SubjPhone      string
	SubjEMail      string
	SubjDNS        string
	SubjEDRPOUCode string
	SubjDRFOCode   string
	IsTimeAvail    bool
	IsTimeStamp    bool
	Time           time.Time
}

type CertInfo struct {
	IsFilled            bool
	Version             int
	Issuer              string
	IssuerCN            string
	Serial              string
	Subject             string
	SubjCN              string
	SubjOrg             string
	SubjOrgUnit         string
	SubjTitle           string
	SubjState           string
	SubjLocality        string
	SubjFullName        string
	SubjAddress         string
	SubjPhone           string
	SubjEMail           string
	SubjDNS             string
	SubjEDRPOUCode      string
	SubjDRFOCode        string
	SubjNBUCode         string
	SubjSPFMCode        string
	SubjOCode           string
	SubjOUCode          string
	SubjUserCode        string
	CertBeginTime       time.Time
	CertEndTime         time.Time
	IsPrivKeyTimesAvail bool
	PrivKeyBeginTime    time.Time
	PrivKeyEndTime      time.Time
	PublicKeyBits       int
	PublicKey           string
	PublicKeyID         string
	IsECDHPublicKey     bool
	ECDHPublicKeyBits   int
	ECDHPublicKey       string
	ECDHPublicKeyID     string
	IssuerPublicKeyID   string
	KeyUsage            string
	ExtKeyUsages        string
	Policies            string
	CRLDistribPoint1    string
	CRLDistribPoint2    string
	IsPowerCert         bool
	IsSubjTypeAvail     bool
	IsSubjCA            bool
}

type TimeInfo struct {
	Version              int
	IsTimeAvail          bool
	IsTimeStamp          bool
	Time                 time.Time
	IsSignTimeStampAvail bool
	SignTimeStamp        time.Time
}

type CertInfoEx struct {
	IsFilled              bool
	Version               int
	Issuer                string
	IssuerCN              string
	Serial                string
	Subject               string
	SubjCN                string
	SubjOrg               string
	SubjOrgUnit           string
	SubjTitle             string
	SubjState             string
	SubjLocality          string
	SubjFullName          string
	SubjAddress           string
	SubjPhone             string
	SubjEMail             string
	SubjDNS               string
	SubjEDRPOUCode        string
	SubjDRFOCode          string
	SubjNBUCode           string
	SubjSPFMCode          string
	SubjOCode             string
	SubjOUCode            string
	SubjUserCode          string
	CertBeginTime         time.Time
	CertEndTime           time.Time
	IsPrivKeyTimesAvail   bool
	PrivKeyBeginTime      time.Time
	PrivKeyEndTime        time.Time
	PublicKeyBits         int
	PublicKey             string
	PublicKeyID           string
	IssuerPublicKeyID     string
	KeyUsage              string
	ExtKeyUsages          string
	Policies              string
	CRLDistribPoint1      string
	CRLDistribPoint2      string
	IsPowerCert           bool
	IsSubjTypeAvail       bool
	IsSubjCA              bool
	ChainLength           int
	UPN                   string
	PublicKeyType         int
	KeyUsageType          int
	RSAModul              string
	RSAExponent           string
	OCSPAccessInfo        string
	IssuerAccessInfo      string
	TSPAccessInfo         string
	IsLimitValueAvailable bool
	LimitValue            int
	LimitValueCurrency    string
	SubjType              int
	SubjSubType           int
	SubjUNZR              string
	SubjCountry           string
	Fingerprint           string
	IsQSCD                bool
	SubjUserID            string
	CertHashType          int
}

type UserInfo struct {
	CommonName   string
	Locality     string
	State        string
	Organization string
	OrgUnit      string
	Title        string
	Street       string
	Phone        string
	Surname      string
	Givenname    string
	EMail        string
	DNS          string
	EDRPOUCode   string
	DRFOCode     string
	NBUCode      string
	SPFMCode     string
	OCode        string
	OUCode       string
	UserCode     string
	UPN          string
	UNZR         string
	Country      string
}

type CertOwnerInfo struct {
	IsFilled       bool
	Issuer         string
	IssuerCN       string
	Serial         string
	Subject        string
	SubjCN         string
	SubjOrg        string
	SubjOrgUnit    string
	SubjTitle      string
	SubjState      string
	SubjLocality   string
	SubjFullName   string
	SubjAddress    string
	SubjPhone      string
	SubjEMail      string
	SubjDNS        string
	SubjEDRPOUCode string
	SubjDRFOCode   string
}

type RequestInfo struct {
	Type                int
	Request             []byte
	FileName            string
	IsFilled            bool
	Version             int
	IsSimple            bool
	Subject             string
	SubjCN              string
	SubjOrg             string
	SubjOrgUnit         string
	SubjTitle           string
	SubjState           string
	SubjLocality        string
	SubjFullName        string
	SubjAddress         string
	SubjPhone           string
	SubjEMail           string
	SubjDNS             string
	SubjEDRPOUCode      string
	SubjDRFOCode        string
	SubjNBUCode         string
	SubjSPFMCode        string
	SubjOCode           string
	SubjOUCode          string
	SubjUserCode        string
	IsCertTimesAvail    bool
	CertBeginTime       time.Time
	CertEndTime         time.Time
	IsPrivKeyTimesAvail bool
	PrivKeyBeginTime    time.Time
	PrivKeyEndTime      time.Time
	PublicKeyType       int
	PublicKeyBits       int
	PublicKey           string
	RSAModul            string
	RSAExponent         string
	PublicKeyID         string
	ExtKeyUsages        string
	CRLDistribPoint1    string
	CRLDistribPoint2    string
	IsSubjTypeAvail     bool
	SubjType            int
	SubjSubType         int
	IsSelfSigned        bool
	SignIssuer          string
	SignSerial          string
	SubjUNZR            string
	SubjCountry         string
	IsQSCD              bool
}

// FileStoreSettings type
type FileStoreSettings struct {
	Path             string
	CheckCRLs        bool
	AutoRefresh      bool
	OwnCRLsOnly      bool
	FullAndDeltaCRLs bool
	AutoDownloadCRLs bool
	SaveLoadedCerts  bool
	ExpireTime       int
}

// ProxySettings type
type ProxySettings struct {
	Use          bool
	Anonymus     bool
	Address      string
	Port         string
	User         string
	Password     string
	SavePassword bool
}

type OCSPSettings struct {
	Use         bool
	BeforeStore bool
	Address     string
	Port        string
}

type TSPSettings struct {
	GetStamps bool
	Address   string
	Port      string
}

type LDAPSettings struct {
	Use      bool
	Address  string
	Port     string
	Anonymus bool
	User     string
	Password string
}

type CMPSettings struct {
	Use        bool
	Address    string
	Port       string
	CommonName string
}

type OCSPAccessInfoModeSettings struct {
	Enabled bool
}

type OCSPAccessInfoSettings struct {
	IssuerCN string
	Address  string
	Port     string
}

type LogSettings struct {
	System         bool
	UseReportAgent bool
	Address        string
	Port           string
	OnlyErrors     bool
}

type ModeSettings struct {
	Offline bool
}

type KeyMedia struct {
	TypeIndex   int
	DeviceIndex int
	Password    string
}

type Context struct {
	Handle unsafe.Pointer
}

type PrivateKeyContext struct {
	Handle unsafe.Pointer
}

type Session struct {
	Handle unsafe.Pointer
}

type AlgoContext struct {
	Handle unsafe.Pointer
}
