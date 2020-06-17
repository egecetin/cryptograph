#pragma once

#include "logger.h"
#include "cryptograph.h"

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

		// Functions
		filer(const char* pathSrc = nullptr);
		
		void setPath(const char* pathSrc);
		void moveFile(const char* pathDest);
		void copyFile(const char* pathDest);
		char* getPath();

		void setCompressionType(COMPRESSION_METHOD id);
		COMPRESSION_METHOD getCompressionType(char* type = nullptr);
		ERR_STATUS compress(const char* pathDest = nullptr);
		ERR_STATUS decompress(const char* pathDest = nullptr);

#ifdef CRYPTOGRAPH_EGE
		void setEncryptionMethod(CRYPTO_METHOD id);
		CRYPTO_METHOD getEncryptionMethod(char* type = nullptr);
		ERR_STATUS encrypt(Ipp8u* key, size_t keylen, const char* pathDest = nullptr);
		ERR_STATUS decrypt(Ipp8u* key, size_t keylen, const char* pathDest = nullptr);
#endif

		~filer();

	private:
		// Variables
		char* path;
		COMPRESSION_METHOD compression_type = NO_COMPRESS;

#ifdef CRYPTOGRAPH_EGE
		CRYPTO_METHOD crypto_type = NO_ENCRYPT;
		IppHashAlgId hash_type;
		Ipp8u* hash_code;
#endif

		// Functions
		char* readLastWrite(const std::experimental::filesystem::path fptr);
		int64_t readSize(const std::experimental::filesystem::path fptr);
		char* strcomptype(COMPRESSION_METHOD id);
		char* strcrypttype(CRYPTO_METHOD id);
	};

	/*******************************************************************************************/
	/**************************************** Functions ****************************************/
	/*******************************************************************************************/

	void copyFile(const char* pathSrc, const char* pathDest);

}