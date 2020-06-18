#pragma once

#include "logger.h"
//#include "cryptograph.h"

#include <cstdio>
#include <cstdint>
#include <chrono>
#include <filesystem>

namespace ege {
	/*******************************************************************************************/
	/*************************************** Definitions ***************************************/
	/*******************************************************************************************/
	
	enum COMPRESSION_METHOD
	{
		NO_COMPRESS
	};

	/*******************************************************************************************/
	/****************************************** Class ******************************************/
	/*******************************************************************************************/

	class filer
	{
	public:
		// Variables
		double progress = 0; // 0 - 100

		// Functions
		filer(char* pathSrc = nullptr);
		
		ERR_STATUS setPath(char* pathSrc);
		ERR_STATUS moveFile(char* pathDest, bool overwrite = true);
		ERR_STATUS copyFile(char* pathDest, bool overwrite = true);
		ERR_STATUS pack(char* pathDest = nullptr, bool overwrite = true);
		ERR_STATUS unpack(char* pathDest = nullptr, bool overwrite = true);
		
		char* getPath();
		int64_t readSize(char* file);
		char* readLastWrite(char* file);

		void setCompressionType(ege::COMPRESSION_METHOD id);
		ege::COMPRESSION_METHOD getCompressionType(char* type = nullptr);

#ifdef CRYPTOGRAPH_EGE
		void setKey(Ipp8u* key, size_t keylen);
		Ipp8u* getKey(size_t &keylen);

		void setEncryptionMethod(ege::CRYPTO_METHOD id);
		ege::CRYPTO_METHOD getEncryptionMethod(char* type = nullptr);

		void setHashMethod(IppHashAlgId id);
		IppHashAlgId getHashMethod(char* type = nullptr);
#endif // CRYPTOGRAPH_EGE

		~filer();

	private:
		// Variables
		char *path = nullptr;
		ege::fileProperties context;
		ege::COMPRESSION_METHOD compression_type = ege::COMPRESSION_METHOD::NO_COMPRESS;		

		// Functions
		bool checkfile(char* file);
		const char* strcomptype(ege::COMPRESSION_METHOD id);		
		ERR_STATUS compress(char* pathSrc, char* pathDest = nullptr);
		ERR_STATUS decompress(char* pathSrc, char* pathDest = nullptr);
		ERR_STATUS copy(char* pathSrc, char* pathDest);
		ERR_STATUS readHeader(char* pathSrc);
		void prepareHeader(char* pathSrc);		
		void writeHeader(char* pathDest);
		void configFromHeader();

#ifdef CRYPTOGRAPH_EGE
		size_t keylen = 0;
		Ipp8u* key = nullptr;
		IppHashAlgId hash_type = ippHashAlg_Unknown;		
		ege::CRYPTO_METHOD crypto_type = ege::CRYPTO_METHOD::NO_ENCRYPT;

		const char* strhashtype(IppHashAlgId id);
		const char* strcrypttype(ege::CRYPTO_METHOD id);
		ERR_STATUS encrypt(char* pathSrc, char* pathDest = nullptr);
		ERR_STATUS decrypt(char* pathSrc, char* pathDest = nullptr);
#endif // CRYPTOGRAPH_EGE
	
	};

	struct fileProperties
	{
		char codeword[5] = "EGE!";
		int64_t size;
		int64_t c_size;
		char filename[FILENAME_MAX];
		char extension[FILENAME_MAX];
		char lastwrite[25];				// std::asctime has fixed 25 character
		size_t compression;
#ifdef CRYPTOGRAPH_EGE
		char extword[5] = "EXT!";
		ege::CRYPTO_METHOD crypto;
		IppHashAlgId hashmethod;
		Ipp8u hashcode[MAX_HASH_LEN];
#endif // CRYPTOGRAPH_EGE
		char endword[5] = "END!";
	};

	/*******************************************************************************************/
	/**************************************** Functions ****************************************/
	/*******************************************************************************************/

}