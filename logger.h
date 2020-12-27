#pragma once

#include <ipp.h>
#include <ctime>
#include <iostream>
#include <fstream>

typedef int ERR_STATUS;

/* Error Classifiers*/
#define IPP_ID		1
#define GEN_ID		2

/* General Error Code Definitions */
#define NO_ERROR				 0
#define UNKNOWN_ERROR			 1
#define TOO_MANY_THREADS		 2

/* File Error Codes */
#define FILE_NOT_SUPPORTED		30
#define FILE_INPUT_OUTPUT_ERR	31
#define FILE_NOT_SET			32
#define FILE_NOT_EXIST			33
#define FILE_ALREADY_EXIST		34
#define OVER_FILENAME_LIMIT		35
#define NOT_A_DIRECTORY			36
#define COMP_UNKNOWN_METHOD		37
#define COMP_CLASS_BROKEN		38

/* Cryptography Error Codes*/
#define CRYPT_BITSIZE_MISMATCH	40
#define CRYPT_UNKNOWN_METHOD	41
#define CRYPT_UNKNOWN_KEY_TYPE	42
#define CRYPT_KEY_NOT_SET		43
#define CRYPT_PASSWORD_ERROR	44

#define HASH_CHECK_FAIL			50
#define HASH_UNKNOWN_METHOD		51

namespace ege {

	/* Functions */
	inline const char* currentDateTime();
	inline const char* sterror(ERR_STATUS code, int id);
	void logger(ERR_STATUS code, int id);
}