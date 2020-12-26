#include "logger.h"

namespace ege {

	inline const char* currentDateTime() {
		time_t     now = time(0);
		struct tm  tstruct;
		static char buf[80];
		localtime_s(&tstruct, &now);
		strftime(buf, sizeof(buf), "%Y-%m-%d_%H%M%S", &tstruct);

		return buf;
	}

	inline const char* GeneralErrorMessage(ERR_STATUS code) {
		switch (code) {
		case CRYPT_BITSIZE_MISMATCH:
			return "Bitsize mismatch at context.";
		default:
			return "Unknown error code";
		}
	}


	inline const char* sterror(ERR_STATUS code, int id) {

		const char *err;
		if (id == IPP_ID)
			err = ippGetStatusString(code);
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