#pragma once

#include <ipp.h>
#include <ctime>
#include <iostream>
#include <fstream>

#include <QDebug>

typedef int ERR_STATUS;

/* Error Classifiers*/
#define IPP_ID		1
#define GEN_ID		2

/* General Error Code Definitions */
#define NO_ERROR				0

/* File Error Codes */
#define FILE_NOT_SUPPORTED		30
#define FILE_INPUT_OUTPUT_ERR	31
#define FILE_NOT_SET			32
#define FILE_NOT_EXIST			33
#define FILE_ALREADY_EXIST		34
#define OVER_FILENAME_LIMIT		35
#define COMP_UNKNOWN_METHOD		36
#define COMP_CLASS_BROKEN		37

/* Cryptography Error Codes*/
#define CRYPT_NOT_SUPPORTED		40
#define CRYPT_BITSIZE_MISMATCH	41
#define CRYPT_UNKNOWN_METHOD	42
#define CRYPT_UNKNOWN_KEY_TYPE	43
#define CRYPT_KEY_NOT_SET		44
#define CRYPT_PASSWORD_ERROR	45

#define HASH_CHECK_FAIL			50

namespace ege {

	/* Functions */
	inline const char* currentDateTime();
	inline const char* sterror(ERR_STATUS code, int id);
	void logger(ERR_STATUS code, int id);
}