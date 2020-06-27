#pragma once

#include <mkl.h>
#include <ipp.h>
#include <ctime>
#include <iostream>
#include <fstream>

#include <QDebug>

typedef int ERR_STATUS;

/* Error Classifiers*/
#define DFTI_ID		1
#define VML_ID		2
#define IPP_ID		3
#define VSLCC_ID	4
#define GEN_ID		5

/* General Error Code Definitions */
#define NO_ERROR				0
#define UNKNOWN_ERROR			1

/* OpenCL Error Codes*/
#define OPENCL_NOT_AVAILABLE	1
#define OPENCL_CONTEXT_FAIL		2
#define OPENCL_NO_DEVICE		3

/* CUDA Error Codes */
#define CUDA_NOT_AVAILABLE		10
#define CUDA_NO_DRIVER			11
#define CUDA_CONTEXT_FAIL		12

/* OpenCV Error Codes*/
#define OPENCV_VIDEO_ERROR		20

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

#define HASH_CHECK_FAIL			50

namespace ege {

	/* Functions */
	inline const char* currentDateTime();
	inline const char* VMLErrorMessage(ERR_STATUS code);
	inline const char* VSLCCErrorMessage(ERR_STATUS code);
	inline const char* sterror(ERR_STATUS code, int id);
	void logger(ERR_STATUS code, int id);

}