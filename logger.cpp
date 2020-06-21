#include "logger.h"

namespace ege {

	inline const char* currentDateTime() {
		time_t     now = time(0);
		struct tm  tstruct;
		char       buf[80];
		localtime_s(&tstruct, &now);
		strftime(buf, sizeof(buf), "%Y-%m-%d_%H%M%S", &tstruct);

		return buf;
	}


	inline const char* VMLErrorMessage(ERR_STATUS code) {
		switch (code) {
		case -1:
			return "The function does not support the preset accuracy mode. The Low Accuracy mode is used instead.";
		case -2:
			return "NULL pointer is passed.";
		case 1:
			return "At least one of array values is out of a range of definition.";
		case 2:
			return "At least one of the input array values causes a divide-by-zero exception or produces an invalid (QNaN) result.";
		case 3:
			return "An overflow has happened during the calculation process.";
		case 4:
			return "An underflow has happened during the calculation process.";
		case 1000:
			return "The execution was completed successfully in a different accuracy mode.";
		default:
			return "Unknown error code.";
		}
	}


	inline const char* VSLCCErrorMessage(ERR_STATUS code) {
		switch (code) {
			/****************VSL Common Codes****************/
		case VSL_ERROR_BADARGS:
			return "Input argument value is not valid.";
		case VSL_ERROR_CPU_NOT_SUPPORTED:
			return "CPU version is not supported.";
		case VSL_ERROR_FEATURE_NOT_IMPLEMENTED:
			return "Feature invoked is not implemented.";
		case VSL_ERROR_MEM_FAILURE:
			return "System cannot allocate memory.";
		case VSL_ERROR_NULL_PTR:
			return "Input pointer argument is NULL.";
		case VSL_ERROR_UNKNOWN:
			return "Unknown error.";
			/****************CC Error Codes****************/
		case VSL_CC_ERROR_NOT_IMPLEMENTED:
			return "Requested functionality is not implemented.";
		case VSL_CC_ERROR_ALLOCATION_FAILURE:
			return "Memory allocation failure.";
		case VSL_CC_ERROR_BAD_DESCRIPTOR:
			return "Task descriptor is corrupted.";
		case VSL_CC_ERROR_SERVICE_FAILURE:
			return "A service function has failed.";
		case VSL_CC_ERROR_EDIT_FAILURE:
			return "Failure while editing the task.";
		case VSL_CC_ERROR_EDIT_PROHIBITED:
			return "You cannot edit this parameter.";
		case VSL_CC_ERROR_COMMIT_FAILURE:
			return "Task commitment has failed.";
		case VSL_CC_ERROR_COPY_FAILURE:
			return "Failure while copying the task.";
		case VSL_CC_ERROR_DELETE_FAILURE:
			return "Failure while deleting the task.";
		case VSL_CC_ERROR_BAD_ARGUMENT:
			return "Bad argument or task parameter.";
		case VSL_CC_ERROR_JOB:
			return "Bad parameter: job.";
		case VSL_CC_ERROR_KIND:
			return "Bad parameter: kind.";
		case VSL_CC_ERROR_MODE:
			return "Bad parameter: mode.";
		case VSL_CC_ERROR_TYPE:
			return "Bad parameter: type.";
		case VSL_CC_ERROR_EXTERNAL_PRECISION:
			return "Bad parameter: external_precision.";
		case VSL_CC_ERROR_INTERNAL_PRECISION:
			return "Bad parameter: internal_precision.";
		case VSL_CC_ERROR_PRECISION:
			return "Incompatible external/internal precisions.";
		case VSL_CC_ERROR_DIMS:
			return "Bad parameter: dims.";
		case VSL_CC_ERROR_XSHAPE:
			return "Bad parameter: xshape.";
		case VSL_CC_ERROR_YSHAPE:
			return "Bad parameter: yshape.";
		case VSL_CC_ERROR_ZSHAPE:
			return "Bad parameter: zshape.";
		case VSL_CC_ERROR_XSTRIDE:
			return "Bad parameter: xstride.";
		case VSL_CC_ERROR_YSTRIDE:
			return "Bad parameter: ystride.";
		case VSL_CC_ERROR_ZSTRIDE:
			return "Bad parameter: zstride.";
		case VSL_CC_ERROR_X:
			return "Bad parameter: x.";
		case VSL_CC_ERROR_Y:
			return "Bad parameter: y.";
		case VSL_CC_ERROR_Z:
			return "Bad parameter: z.";
		case VSL_CC_ERROR_START:
			return "Bad parameter: start.";
		case VSL_CC_ERROR_DECIMATION:
			return "Bad parameter: decimation.";
		case VSL_CC_ERROR_OTHER:
			return "Another error.";
		default:
			return "Unknown error code";
		}
	}


	inline const char* GeneralErrorMessage(ERR_STATUS code) {
		switch (code) {
		case OPENCL_NOT_AVAILABLE:
			return "OpenCL is not available.";
		case OPENCL_CONTEXT_FAIL:
			return "Failed creating the context (OpenCL).";
		case OPENCL_NO_DEVICE:
			return "No OpenCL devices detected.";
		case CUDA_NOT_AVAILABLE:
			return "CUDA is not available.";
		case CUDA_NO_DRIVER:
			return "CUDA driver is not installed or version is not supported.";
		case CUDA_CONTEXT_FAIL:
			return "Failed creating the context (CUDA).";
		case OPENCV_VIDEO_ERROR:
			return "Can't open video file.";
		case CRYPT_BITSIZE_MISMATCH:
			return "Bitsize mismatch at context.";
		default:
			return "Unknown error code";
		}
	}


	inline const char* sterror(ERR_STATUS code, int id) {

		const char *err;
		if (id == DFTI_ID)
			err = DftiErrorMessage(code);
		else if (id == VML_ID)
			err = VMLErrorMessage(code);
		else if (id == IPP_ID)
			err = ippGetStatusString(code);
		else if (id == VSLCC_ID)
			err = VSLCCErrorMessage(code);
		else if (id == GEN_ID)
			err = GeneralErrorMessage(code);
		else
			err = "Unknown error classification.";

		return err;
	}


	void logger(ERR_STATUS code, int id) {
		std::fstream fptr;
		fptr.open("log.txt", std::ios_base::app | std::ios::binary);
		if (fptr.fail())
			return;
		if (id == 0)
			fptr << "\n--------------------\t" << currentDateTime() << "\t--------------------\n";
		else if (id != -1)
			fptr << currentDateTime() << ":\t" << sterror(code, id) << "\n";
		else
			fptr << "--------------------\t" << "End of execution at " << currentDateTime() << "\t--------------------\n\n\n";
		fptr.flush();
		fptr.close();
	}

}