#ifndef STRING_CODER_H
#define STRING_CODER_H

//================================================================================

#ifndef OS_NIX
	#include <windows.h>
#else
	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0 
#endif

#define CP_UTF8		65001
#define CP_ACP		1251

extern "C" 
	int WideCharToMultiByte(
		unsigned int CodePage,
		unsigned long dwFlags,
		const wchar_t* lpWideCharStr,
		int cchWideChar,
		char* lpMultiByteStr,
		int cbMultiByte,
		char* lpDefaultChar,
		unsigned int* lpUsedDefaultChar);

extern "C" 
	int MultiByteToWideChar(
		unsigned int CodePage,
		unsigned long dwFlags,
		const char* lpMultiByteStr,
		int cbMultiByte,
		wchar_t* lpWideCharStr,
		int cchWideChar);
#endif

//================================================================================

int ConvertString(
	unsigned int		uiSrcEncoding,
	const char*			pszSrc,
	unsigned int		uiDstEncoding,
	char*				*ppszDst);

int ConvertString(
	unsigned int		uiSrcEncoding,
	const char*			pszSrc,
	unsigned int		uiDstEncoding,
	char*				pszDst,
	unsigned int		nDstMaxSize);

int StringArrayToString(
	const char*			*ppszSrc,
	unsigned long		dwCount,
	char*				*ppszDst);

//================================================================================

#endif // STRING_CODER_H
