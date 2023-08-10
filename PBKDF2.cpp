/*
* Copyright (c) 2017-2023, DB Systel GmbH
* Copyright (c) 2023, Frank Schwab
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
* in the documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
* BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* Author: Frank Schwab
*
* Version: 2.1.0
*
* Example program to show correct and incorrect password storage with the PBKDF2 function
*
* Changes:
*     2015-05-26: V1.0.0: Created
*     2015-09-22: V2.0.0: Have a choice of hash types
*     2017-03-03: V2.1.0: Cleaned up data types for counts and lengths
*     2017-03-03: V2.2.0: Removed unnecessary methods and make hex char conversion to byte a bit faster
*/

/*
 * INCLUDES
 */
#include "stdafx.h"

#include <windows.h>

#include <math.h>
#include <bcrypt.h>

/*
 * DEFINES
 */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

/*
 * TYPDEFS
 */

/*
 * TOCTET is a data type that defines 8 binary bits and is *not* a character
 * (Welcome to the strange world of C).
 */
typedef UCHAR TOCTET;

/*
 * Define a default "unsuccessful" NT STATUS for initialization.
 * This is not a true NTSTATUS.
 */
#ifndef NTSTATUS_UNSUCCESSFUL
#define NTSTATUS_UNSUCCESSFUL (-1)
#endif

/*
 * Minimum and maximum values for the hash type
 */
#define MIN_HASH_TYPE 1
#define MAX_HASH_TYPE 5

 /*
  * Minimum and maximum value of the salt if it is interpreted as an integer
  */
#define MIN_SALT 0
#define MAX_SALT INT_MAX

/*
 * Minimum and maximum value of the iteration count if it is interpreted as an integer
 */
#define MIN_ITERATION_COUNT 1
#define MAX_ITERATION_COUNT 5000000


/*
 * Argument macros
 */
#define ARGV_HASH_TYPE       argv[1]
#define ARGV_SALT            argv[2]
#define ARGV_ITERATION_COUNT argv[3]
#define ARGV_PASSWORD        argv[4]

/*
 * Macros for error checking
 */
#define RESET_ERROR_MSG      *errorBuffer = _T('\0') 
#define IS_ERROR_MSG_SET     *errorBuffer != _T('\0') 
#define IS_ERROR_MSG_NOT_SET *errorBuffer == _T('\0') 

/*
 * Variables for duration measurement
 */
LARGE_INTEGER startTickValue;
double tickDuration = 0.0;

/*
 * Start the timer for duration measurement
 */
void startTimer()
{
	QueryPerformanceCounter(&startTickValue);
}

/*
 * Get the time in seconds of one timer tick
 */
void getTickDuration()
{
	LARGE_INTEGER frequency;

	QueryPerformanceFrequency(&frequency);

	tickDuration = 1.0 / frequency.QuadPart;
}

/*
 * Get the number of elapsed timer ticks
 */
long long getElapsedTicks()
{
	LARGE_INTEGER now;

	QueryPerformanceCounter(&now);

	return (now.QuadPart - startTickValue.QuadPart);
}

/*
 * Get elapsed time
 */
double getElapsedTime()
{
   long long elapsedTicks = getElapsedTicks();

	if (tickDuration == 0.0)
		getTickDuration();

	return (elapsedTicks * tickDuration);
}


/*
 * Convert a string into an integer with bounds checking
 */
int getIntegerArg(const TCHAR * pArgName, const TCHAR * pArg, const int minValue, const int maxValue, TCHAR * const errorBuffer, const SIZE_T errorBufferSize)
{
	int result;

	RESET_ERROR_MSG;

	result = _ttoi(pArg);

	if (errno != 0)
	{
		_stprintf_s(errorBuffer, errorBufferSize, _T("\"%s\" is not an integer\n"), pArgName);

		return 0;
	}

	if (result < minValue)
	{
		_stprintf_s(errorBuffer, errorBufferSize, _T("\"%s\" is smaller than minimum value of %d\n"), pArgName, minValue);

		return 0;
	}

	if (result > maxValue)
	{
		_stprintf_s(errorBuffer, errorBufferSize, _T("\"%s\" is larger than maximum value of %d\n"), pArgName, maxValue);

		return 0;
	}

	return result;
}

/*
 * Hexadecimal characters for conversion into hex string
 */
const TCHAR * const HEX_DIGITS = _T("0123456789ABCDEF");

/*
 * Convert a byte buffer into a string of hexadecimal characters separated by blanks
 */
TCHAR * bytesToHex(const TOCTET * const byteBuffer, const SIZE_T bufferSize)
{
	SIZE_T resultSize = bufferSize * 3;

	TCHAR * pResult = (TCHAR *)malloc(resultSize * sizeof(TCHAR));

	if (pResult != NULL)
	{
		TCHAR * pActResult = pResult;
		const TOCTET * pActByte = byteBuffer;

		for (int j = 1; j <= bufferSize; j++)
		{
			int v = (*pActByte) & 0xff;

			*pActResult = HEX_DIGITS[v >> 4]; pActResult++;

			*pActResult = HEX_DIGITS[v & 0x0f]; pActResult++;

			*pActResult = ' '; pActResult++;

			pActByte++;
		}

		pActResult--;
		*pActResult = _T('\0');
	}

	return pResult;
}

/*
 * Get the value of one hexadecimal character as a byte
 */
TOCTET getHexCharValue(const TCHAR hexChar)
{
   int workValue;
   
   /*
    * This method works on a very low level. It subtracts the base values
    * of the valid characters to obtain the corresponding byte value.
    */
   workValue = (int)hexChar - (int)_T('0');

   if (workValue >= 0)
      if (workValue <= 9)
         return (TOCTET) workValue;
      else
      {
         workValue -= _T('A') - _T('0') - 10;
         if (workValue >= 10)
            if (workValue <= 15)
               return (TOCTET) workValue;
            else
            {
               workValue -= _T('a') - _T('A');
               if (workValue >= 10)
                  if (workValue <= 15)
                     return (TOCTET) workValue;
            }
      }

   // If we get here the character was not a valid hex character
   return (TOCTET) 255;
}

/*
 * Convert a string of upper case hexadecimal characters into a byte array
 */
TOCTET * hexStringToByteArray(const TCHAR * const hexText, const SIZE_T hexTextSize, SIZE_T * const byteArraySize, TCHAR * const errorBuffer, const SIZE_T errorBufferSize)
{
	RESET_ERROR_MSG;

	bool isHexTextSizeOdd = ((hexTextSize & 1) != 0);

	SIZE_T allocationSize = (hexTextSize >> 1);

	if (isHexTextSizeOdd)
		allocationSize++;

	TOCTET * result = (TOCTET *)malloc(allocationSize);

	if (result != NULL)
	{
		*byteArraySize = allocationSize;

		const TCHAR * pActChar = hexText;
		TOCTET * pActByte = result;
		TOCTET actValue;
		TOCTET byteValue = 0;

		bool isLowNibble = isHexTextSizeOdd;

		for (SIZE_T actPos = 1; actPos <= hexTextSize; actPos++)
		{
			actValue = getHexCharValue(*pActChar);

			if (actValue <= 15)
			{
				if (isLowNibble)
				{
					*pActByte = (byteValue | actValue);
					pActByte++;
				}
				else
					byteValue = actValue << 4;
			}
			else
			{
				_stprintf_s(errorBuffer, errorBufferSize, _T("Invalid hex character \'%c\' at position %zu of hex string \"%s\"\n"), *pActChar, actPos, hexText);
				break;
			}

			isLowNibble = !isLowNibble;

			pActChar++;
		}
	}
	else
		_stprintf_s(errorBuffer, errorBufferSize, _T("Could not allocate %zu bytes for hex conversion byte array\n"), *byteArraySize);

	return result;
}

/*
 * Convert a string of hexadecimal characters into a byte array
 */
void safeHexStringToByteArray(TCHAR * const hexText, TOCTET ** byteArray, SIZE_T * const byteArraySize, TCHAR * const errorBuffer, const SIZE_T errorBufferSize)
{
	const SIZE_T hexTextSize = _tcslen(hexText);

	*byteArray = hexStringToByteArray(hexText, hexTextSize, byteArraySize, errorBuffer, errorBufferSize);
}

#ifndef _UNICODE
/*
 * If we are in ANSI mode we need a method to convert an ANSI string into an UTF-16 string
 */
void getPasswordUTF16Encoding(const TCHAR * const password,
	const int passwordSize,
	wchar_t ** passwordInUTF16,
	int * const pPasswordInUTF16Size,
	TCHAR * const errorBuffer,
	const SIZE_T errorBufferSize)
{
	RESET_ERROR_MSG;

	int bufferSize;

	*pPasswordInUTF16Size = MultiByteToWideChar(CP_ACP, 0, password, passwordSize, NULL, 0);

	bufferSize = *pPasswordInUTF16Size * sizeof(wchar_t);
	*passwordInUTF16 = (wchar_t *)malloc(bufferSize);

	if (*passwordInUTF16 != NULL)
		MultiByteToWideChar(CP_ACP, 0, password, passwordSize, *passwordInUTF16, *pPasswordInUTF16Size);
	else
		_stprintf_s(errorBuffer, errorBufferSize, _T("Could not allocate %d bytes for passwordInUTF16\n"), bufferSize);
}
#endif

/*
 * Convert the password from the native format (Unicode or ANSI) into the UTF-8 encoding as a byte array
 */
void getPasswordUTF8Encoding(const TCHAR * const password,
	const SIZE_T passwordSize,
	TOCTET ** passwordInUTF8,
	SIZE_T * const pPasswordInUTF8Size,
	TCHAR * const errorBuffer,
	const SIZE_T errorBufferSize)
{
	RESET_ERROR_MSG;

#ifdef _UNICODE
	/*
 	 * If we are in Unicode mode we just convert the UTF-16 characters to UTF-8
	 */
	*pPasswordInUTF8Size = WideCharToMultiByte(CP_UTF8, 0, password, (int)passwordSize, NULL, 0, NULL, NULL);

	*passwordInUTF8 = (TOCTET *)malloc(*pPasswordInUTF8Size);

	if (*passwordInUTF8 != NULL)
		WideCharToMultiByte(CP_UTF8, 0, password, (int)passwordSize, (LPSTR)*passwordInUTF8, (int)*pPasswordInUTF8Size, NULL, NULL);
	else
		_stprintf_s(errorBuffer, errorBufferSize, _T("Could not allocate %zu bytes for passwordInUTF8\n"), *pPasswordInUTF8Size);
#else
	/*
	 * If we are in ANSI mode we first need to convert the ANSI characters to UTF-16 and then from UTF-16 to UTF-8
	 */

	// First convert ANSI to UTF-16
	int passwordInUnicodeSize;
	wchar_t * passwordInUnicode;

	getPasswordUTF16Encoding(password, passwordSize, &passwordInUnicode, &passwordInUnicodeSize, errorBuffer, errorBufferSize);

	if (passwordInUnicode != NULL)
	{
		// Then convert UTF-16 to UTF-8
		*pPasswordInUTF8Size = WideCharToMultiByte(CP_UTF8, 0, passwordInUnicode, passwordInUnicodeSize, NULL, 0, NULL, NULL);

		*passwordInUTF8 = (TOCTET *)malloc(*pPasswordInUTF8Size);

		if (*passwordInUTF8 != NULL)
			WideCharToMultiByte(CP_UTF8, 0, passwordInUnicode, passwordInUnicodeSize, (LPSTR)*passwordInUTF8, *pPasswordInUTF8Size, NULL, NULL);
		else
			_stprintf_s(errorBuffer, errorBufferSize, _T("Could not allocate %d bytes for passwordInUTF8\n"), *pPasswordInUTF8Size);

		free((void *)passwordInUnicode);
	}
#endif
}

/*
 * Calculate the value of PBKDF2 for a password in UTF-8 encoding, a salt as a byte array an an iteration count.
 */
void calculatePBKDF2(TOCTET ** ppDerivedKey, 
	SIZE_T * const pDerivedKeySize, 
	LPCWSTR pHashType,
	TOCTET * pSalt, 
	SIZE_T saltSize, 
	int iterationCount, 
	TOCTET * password, 
	SIZE_T passwordSize,
	TCHAR * const errorBuffer,
	const SIZE_T errorBufferSize)
{
	BCRYPT_ALG_HANDLE handleHash = NULL;

	ULONG outputSize;

	NTSTATUS status = NTSTATUS_UNSUCCESSFUL;

	const TCHAR * const apiErrorMessage = _T("Error 0x%x returned by %s\n");

	RESET_ERROR_MSG;

	//Open an algorithm handle to an HMAC
	if (NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&handleHash,
		pHashType,
		NULL,
		BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		// Get the size of the hash
		if (NT_SUCCESS(status = BCryptGetProperty(handleHash,
			BCRYPT_HASH_LENGTH,
			(PUCHAR)  pDerivedKeySize,
			(ULONG)   sizeof(int),
			(ULONG *) &outputSize,
			(ULONG)   0)))
		{
			// Allocate space for the hash result
			*ppDerivedKey = (TOCTET *) malloc(*pDerivedKeySize);

			if (*ppDerivedKey != NULL)
			{
				//Calculate PBKDF2 with the hash
				if (!NT_SUCCESS(status = BCryptDeriveKeyPBKDF2(
					handleHash,
					password,
					(ULONG)     passwordSize,
					(PUCHAR)    pSalt,
					(ULONG)     saltSize,
					(ULONGLONG) iterationCount,
					(PUCHAR)    *ppDerivedKey,
					(ULONG)     *pDerivedKeySize,
					(ULONG)     0)))
					_stprintf_s(errorBuffer, errorBufferSize, apiErrorMessage, status, _T("BCryptDeriveKeyPBKDF2"));
			}
			else
				_stprintf_s(errorBuffer, errorBufferSize, _T("Could not allocate %zu bytes for hash value\n"), *pDerivedKeySize);
		}
		else
			_stprintf_s(errorBuffer, errorBufferSize, apiErrorMessage, status, _T("BCryptGetProperty"));
		
		BCryptCloseAlgorithmProvider(handleHash, (ULONG) 0);
	}
	else
		_stprintf_s(errorBuffer, errorBufferSize, apiErrorMessage, status, _T("BCryptOpenAlgorithmProvider"));
}

/*
 * Check whether a given file handle is a console or a file. "Redirected" means that the console is redirected to a file
 */
bool isHandleRedirected(const HANDLE handle)
{
	DWORD mode;

	// GetConsoleMode only returns 0 if the handle points to the console
	return (GetConsoleMode(handle, &mode) == 0);
}

/*
* Write a text buffer to a file handle
*/
void writeBuffer(const HANDLE fileHandle, const bool isRedirected, TCHAR * const text)
{
	DWORD charsWritten;

	if (!isRedirected)
	{
#ifndef _UNICODE
		// This does not make sense, at all! The name of the next function is "WriteConsoleA" in ANSI mode so it
		// should expect ANSI encoded strings and convert them to the console's code page. 
		// But in fact it expects OEM encoded strings and so we have to convert to OEM encoded strings
		// before calling WriteConsoleA. This is simply plain wrong.
		CharToOem(text, text);
#endif

		WriteConsole(fileHandle, text, (DWORD) _tcslen(text), &charsWritten, NULL);  // This writes characters
	}
	else
	{
		WriteFile(fileHandle, text, (DWORD) _tcslen(text) * sizeof(TCHAR), &charsWritten, NULL); // But this writes bytes
	}
}

// List of hash algorithms that can be used
LPCWSTR HASH_ALGORITHM[5] = { BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALGORITHM };

/*
 * The main program
 */
int _tmain(const int argc, TCHAR * const argv[])
{
   const SIZE_T errorBufferSize = 499;
	TCHAR errorBuffer[errorBufferSize + 1];  // Bloody stupid null termination character

	int returnValue = 0;

	HANDLE outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE errorHandle = GetStdHandle(STD_ERROR_HANDLE);

	bool isOutputRedirected = isHandleRedirected(outputHandle);
	bool isErrorRedirected = isHandleRedirected(errorHandle);

	TOCTET * releasePassword = NULL;
	TOCTET * releaseSalt = NULL;
	TOCTET * releaseDerivedKey = NULL;

	if (argc >= 5)
	{
		//Should I do it right or not?
		bool doItRight = (argc >= 6);

		// 1. Get the hash type

		int hashType;

	    hashType = getIntegerArg(_T("hashType"), ARGV_HASH_TYPE, MIN_HASH_TYPE, MAX_HASH_TYPE, errorBuffer, errorBufferSize) - 1;

		if (IS_ERROR_MSG_SET) {
			writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

			returnValue = 2;
			goto Exit;
		}

		// 2. Get the salt

		int salt;
		SIZE_T saltArraySize;
		TOCTET * saltArray;

		if (doItRight) {
			/*
			* If we should do it right we interpret the salt as an array of bytes
			*/
			safeHexStringToByteArray(ARGV_SALT, &saltArray, &saltArraySize, errorBuffer, errorBufferSize);
			releaseSalt = saltArray;
		}
		else
		{
			/*
			* If we should to it wrong we interpret the salt as an integer
			*/
			salt = getIntegerArg(_T("salt"), ARGV_SALT, MIN_SALT, MAX_SALT, errorBuffer, errorBufferSize);

			saltArraySize = sizeof(salt);
			saltArray = (TOCTET *)&salt;
		}

		if (IS_ERROR_MSG_SET) {
			writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

			returnValue = 2;
			goto Exit;
		}

		// 3. Get the iteration count

		int iterationCount = getIntegerArg(_T("iterationCount"), ARGV_ITERATION_COUNT, MIN_ITERATION_COUNT, MAX_ITERATION_COUNT, errorBuffer, errorBufferSize);

		if (IS_ERROR_MSG_SET) {
			writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

			returnValue = 2;
			goto Exit;
		}

		// 4. Get the password

		//Attention: password has been converted from OEM code page to Windows character set (A) or UTF-16 (W)!
		const TCHAR * const password = ARGV_PASSWORD;
		const SIZE_T passwordSize = _tcslen(password);

		SIZE_T passwordBytesSize = 0;
		TOCTET * passwordBytes = NULL;

		if (doItRight)
		{
			/*
 			 * If we should do it right we now get the UTF-8 encoding of the password
 			 */
			SIZE_T passwordInUTF8Size = 0;
			TOCTET * passwordInUTF8 = NULL;

			getPasswordUTF8Encoding(password, passwordSize, &passwordInUTF8, &passwordInUTF8Size, errorBuffer, errorBufferSize);

			if (IS_ERROR_MSG_NOT_SET) {
				passwordBytesSize = passwordInUTF8Size;
				passwordBytes = passwordInUTF8;
				releasePassword = passwordInUTF8;
			}
			else
			{
				writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

				returnValue = 3;
				goto Exit;
			}
		}
		else
		{
			/*
			 * If we should do it wrong we use the password as it is. I.e. ANSI characters in ANSI mode and UTF-16 characters in Unicode mode.
			 */
			passwordBytesSize = _tcslen(password) * sizeof(TCHAR);
			passwordBytes = (TOCTET*)password;
		}

		/*
		 * Finally we get to the point. Here we calculate the PBKDF2 and measure the time duration needed to calculate it
		 */
		SIZE_T derivedKeySize = 0;
		TOCTET * pDerivedKey = NULL;

		startTimer();
		calculatePBKDF2(&pDerivedKey, &derivedKeySize, HASH_ALGORITHM[hashType], saltArray, saltArraySize, iterationCount, passwordBytes, passwordBytesSize, errorBuffer, errorBufferSize);
		double duration = getElapsedTime();

		releaseDerivedKey = pDerivedKey;

		if (IS_ERROR_MSG_NOT_SET) {
			TCHAR * saltText;

			if (doItRight)
				saltText = bytesToHex(saltArray, saltArraySize);
			else
			{
				saltText = (TCHAR *)malloc(20 * sizeof(TCHAR));

				if (saltText != NULL)
					_itot_s(*(int *)saltArray, saltText, 20, 10);
			}

			if (saltText != NULL)
			{
				// Print the parameters and the result
				const TCHAR * const pbkdf2AsText = bytesToHex(pDerivedKey, derivedKeySize);
				_stprintf_s(errorBuffer, errorBufferSize, _T("HashType: %ws, Salt: %s, IterationCount: %d, Password: \'%s\', PBKDF2: %s\n"), HASH_ALGORITHM[hashType], saltText, iterationCount, password, pbkdf2AsText);
				writeBuffer(outputHandle, isOutputRedirected, errorBuffer);

				free((void *)saltText);
				free((void *)pbkdf2AsText);

				// Print the time measurement
				_stprintf_s(errorBuffer, errorBufferSize, _T("Duration: %d ms\n"), lround(duration * 1000));
				writeBuffer(outputHandle, isOutputRedirected, errorBuffer);
			}
			else
			{
				_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("Could not allocate salt text array\n"));
				writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

				returnValue = 3;
				goto Exit;
			}
		}
		else {
			writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

			returnValue = 2;
			goto Exit;
		}
	}
	else
	{
		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("Not enough arguments\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("Usage: pbkdf2 <hashType> <salt> <iterationCount> <password> [doItRight]\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("       hashType: 1=SHA-1, 2=SHA-256, 3=SHA384, 5=SHA512\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("       doItRight: If present the salt is interpreted as a byte array and\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("                  the password is converted to UTF-8 before hashing\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("                  Otherwise the salt is interpreted as an integer and\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		_tcscpy_s(errorBuffer, sizeof(errorBuffer), _T("                  the password is used in the ANSI or UTF-16 encoding\n"));
		writeBuffer(errorHandle, isErrorRedirected, errorBuffer);

		returnValue = 1;
	}

Exit:
	if (releasePassword != NULL)
		free((void *)releasePassword);

	if (releaseSalt != NULL)
		free((void *)releaseSalt);

	if (releaseDerivedKey != NULL)
		free((void *)releaseDerivedKey);

	return returnValue;
}
