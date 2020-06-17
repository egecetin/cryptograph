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
		filer(char* pathSrc = nullptr);
		
		ERR_STATUS setPath(char* pathSrc);
		ERR_STATUS moveFile(char* pathDest);
		ERR_STATUS copyFile(char* pathDest);
		ERR_STATUS pack(char* pathDest = nullptr, bool overwrite = true);
		ERR_STATUS unpack(char* pathDest = nullptr, bool overwrite = true);
		char* getPath();

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
		ege::COMPRESSION_METHOD compression_type = ege::COMPRESSION_METHOD::NO_COMPRESS;

		// Functions		
		int64_t readSize(char* file);
		char* readLastWrite(char* file);
		bool checkfile(char* file);
		const char* strcomptype(ege::COMPRESSION_METHOD id);		
		ERR_STATUS compress(const char* pathDest = nullptr);
		ERR_STATUS decompress(const char* pathDest = nullptr);


#ifdef CRYPTOGRAPH_EGE
		size_t keylen = 0;
		Ipp8u* key = nullptr;
		IppHashAlgId hash_type = ippHashAlg_Unknown;		
		ege::CRYPTO_METHOD crypto_type = ege::CRYPTO_METHOD::NO_ENCRYPT;

		const char* strhashtype(IppHashAlgId id);
		const char* strcrypttype(ege::CRYPTO_METHOD id);
		ERR_STATUS encrypt(char* pathDest = nullptr);
		ERR_STATUS decrypt(char* pathDest = nullptr);
#endif // CRYPTOGRAPH_EGE


	};

	/*******************************************************************************************/
	/**************************************** Functions ****************************************/
	/*******************************************************************************************/

}