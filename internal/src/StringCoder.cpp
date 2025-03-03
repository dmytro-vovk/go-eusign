//================================================================================

#include "StringCoder.h"

//================================================================================

int ConvertString(
	unsigned int		uiSrcEncoding,
	const char*			pszSrc,
	unsigned int		uiDstEncoding,
	char*				*ppszDst)
{
	wchar_t*			pwszTmp;
	unsigned long		dwTmp;
	char*				pszResult;
	unsigned long		dwResult;

#ifndef OS_NIX
	SetLastError(0);
#endif // OS_NIX

	dwTmp = MultiByteToWideChar(uiSrcEncoding, 0,
		pszSrc, -1, NULL, 0);
	if (dwTmp == 0
#ifndef OS_NIX
		|| GetLastError() != 0
#endif // OS_NIX
		)
	{
		return FALSE;
	}

	pwszTmp = new wchar_t[dwTmp + 1];
	if (pwszTmp == NULL)
		return FALSE;

	pwszTmp[dwTmp] = L'\0';

	if (!MultiByteToWideChar(uiSrcEncoding, 0,
			pszSrc, -1, pwszTmp, dwTmp))
	{
		delete[] pwszTmp;
		return FALSE;
	}

#ifndef OS_NIX
	SetLastError(0);
#endif // OS_NIX

	dwResult = WideCharToMultiByte(uiDstEncoding, 0,
		pwszTmp, -1, NULL, 0, NULL, NULL);
	if (dwResult == 0 
#ifndef OS_NIX
		|| GetLastError() != 0
#endif // OS_NIX
		)
	{
		delete[] pwszTmp;
		return FALSE;
	}

	pszResult = new char[dwResult];
	if (pszResult == NULL)
	{
		delete[] pwszTmp;
		return FALSE;
	}

	if (!WideCharToMultiByte(uiDstEncoding, 0, 
			pwszTmp, -1, pszResult, dwResult,
			NULL, NULL))
	{
		delete[] pwszTmp;
		delete[] pszResult;

		return FALSE;
	}

	delete[] pwszTmp;

	*ppszDst = pszResult;

	return TRUE;
}

//--------------------------------------------------------------------------------

int ConvertString(
	unsigned int		uiSrcEncoding,
	const char*			pszSrc,
	unsigned int		uiDstEncoding,
	char*				pszDst,
	unsigned int		nDstMaxSize)
{
	char*				pszTmp;

	if (!ConvertString(
			uiSrcEncoding, pszSrc,
			uiDstEncoding, &pszTmp))
	{
		return FALSE;
	}

	if ((strlen(pszTmp) + 1) > nDstMaxSize)
	{
		delete[] pszTmp;
		return FALSE;
	}

	strcpy(pszDst, pszTmp);
	delete[] pszTmp;

	return TRUE;
}

//--------------------------------------------------------------------------------

int StringArrayToString(
	const char*			*ppszSrc,
	unsigned long		dwCount,
	char*				*ppszDst)
{
	unsigned long		dwCurLength;
	unsigned long		dwLength;
	unsigned long		dwI;
	char*				pszDst;
	char*				pszCur;

	if (ppszSrc == NULL)
		dwCount = 0;

	dwLength = 1;
	for (dwI = 0; dwI < dwCount; dwI++)
		dwLength += strlen(ppszSrc[dwI]);

	pszDst = new char[dwLength + 1];
	if (pszDst == NULL)
		return FALSE;

	memset(pszDst, 0, dwLength + 1);

	pszCur = pszDst;
	for (dwI = 0; dwI < dwCount; dwI++)
	{
		dwCurLength = strlen(ppszSrc[dwI]) + 1;
		memcpy(pszCur, ppszSrc[dwI], dwCurLength);
		pszCur += dwCurLength;
	}

	if (ppszDst)
		*ppszDst = pszDst;
	else
		delete[] pszDst;

	return TRUE;
}

//================================================================================
