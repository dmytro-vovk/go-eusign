package eusign

import "github.com/dmytro-vovk/go-eusign/internal/src"

type HashAlgo int

const (
	HashUnknown   HashAlgo = src.CtxHashAlgoUnknown
	HashGOST34311 HashAlgo = src.CtxHashAlgoGOST34311
	HashSHA160    HashAlgo = src.CtxHashAlgoSHA160
	HashSHA224    HashAlgo = src.CtxHashAlgoSHA224
	HashSHA256    HashAlgo = src.CtxHashAlgoSHA256
	HashSHA384    HashAlgo = src.CtxHashAlgoSHA384
	HashSHA512    HashAlgo = src.CtxHashAlgoSHA512
	HashDSTU256   HashAlgo = src.CtxHashAlgoDSTU256
	HashDSTU384   HashAlgo = src.CtxHashAlgoDSTU384
	HashDSTU512   HashAlgo = src.CtxHashAlgoDSTU512
)

type SignAlgo int

const (
	SignUnknown               SignAlgo = src.SignTypeUnknown
	SignDSTU4145WithGOST34311 SignAlgo = src.CtxSignDSTU4145WithGOST34311
	SignRSAWithSHA            SignAlgo = src.CtxSignRSAWithSHA
	SignECDSAWithSHA          SignAlgo = src.CtxSignECDSAWithSHA
	SignDSTU4145WithDSTU7564  SignAlgo = src.CtxSignDSTU4145WithDSTU7564
)
