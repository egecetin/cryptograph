#pragma once

#include <mkl.h>
#include <ipp.h>
#include <ctime>
#include <iostream>
#include <fstream>

typedef int ERR_STATUS;

/* Error Classifiers*/
#define DFTI_ID		1
#define VML_ID		2
#define IPP_ID		3
#define VSLCC_ID	4
#define GEN_ID		5

/* General Error Code Definitions */
#define NO_ERROR				0

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

/* IPP Cryptography Codes */
#define IPPCP_BITSIZE_MISMATCH	30

namespace ege {

	/* Functions */
	inline const char* currentDateTime();
	inline const char* VMLErrorMessage(ERR_STATUS code);
	inline const char* VSLCCErrorMessage(ERR_STATUS code);
	inline const char* sterror(ERR_STATUS code, int id);
	void logger(ERR_STATUS code, int id);

}