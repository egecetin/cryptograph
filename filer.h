#pragma once

#include "logger.h"
#include "cryptograph.h"

#include <cstdio>
#include <cstdint>
#include <chrono>
#include <filesystem>

#define BUFFER_SIZE	 65536	//  64 kB
#define COMP_BUFSIZ	131072	// 128 kB
#define COMP_EXTEND	   512	// 0.5 kB

namespace ege {
	/*******************************************************************************************/
	/*************************************** Definitions ***************************************/
	/*******************************************************************************************/
	
	enum COMPRESSION_METHOD
	{
		NO_COMPRESS,
		LZSS,			// Lempel-Ziv-Storer-Szymansk
		ZLIB_FAST,		// (Reserved)
		ZLIB_AVERAGE,	// (Reserved)
		ZLIB_SLOW,		// (Reserved)
		LZO_FAST,		// Lempel-Ziv-Oberhumer (IppLZO1X1ST)
		LZO_SLOW,		// Lempel-Ziv-Oberhumer (IppLZO1XST)
		LZ4,
		LZ4_HC			// High-compression mode (Reserved)
	};
	
	/*******************************************************************************************/
	/****************************************** Class ******************************************/
	/*******************************************************************************************/
	
	/*************************************** File Header ***************************************/
	struct fileProperties
	{
		int64_t size;
		int64_t c_size;
		char filename[FILENAME_MAX];
		char extension[FILENAME_MAX];
		char lastwrite[25];				// std::asctime has fixed 25 character
		ege::COMPRESSION_METHOD compression;
		int crypto_check;				// for compatibility
#ifdef CRYPTOGRAPH_EGE
		ege::CRYPTO_METHOD crypto;
		IppHashAlgId hashmethod;
		Ipp8u hashcode[MAX_HASH_LEN];
#endif // CRYPTOGRAPH_EGE
	};

	/*************************************** FileHandler ***************************************/
	class Filer
	{
	public:
		// Variables
		double progress = 0; // Between 0 - 100

		// Functions
		Filer(char* pathSrc = nullptr);
		
		ERR_STATUS setPath(char* pathSrc);
		ERR_STATUS moveFile(char* pathDest, bool overwrite = false);
		ERR_STATUS copyFile(char* pathDest, bool overwrite = false);
		ERR_STATUS pack(char* pathDest = nullptr, bool overwrite = false);
		ERR_STATUS unpack(char* pathDest = nullptr, bool overwrite = false);
		
		char* getPath();
		int64_t readSize(char* file);
		char* readLastWrite(char* file);

		void setCompressionType(ege::COMPRESSION_METHOD id);
		ege::COMPRESSION_METHOD getCompressionType(char* type = nullptr);

#ifdef CRYPTOGRAPH_EGE
		void setKey(Ipp8u* key, size_t keylen);
		Ipp8u* getKey(size_t *keylen);

		void setEncryptionMethod(ege::CRYPTO_METHOD id);
		ege::CRYPTO_METHOD getEncryptionMethod(char* type = nullptr);

		void setHashMethod(IppHashAlgId id);
		IppHashAlgId getHashMethod(char* type = nullptr);
#endif // CRYPTOGRAPH_EGE

		~Filer();

	private:
		// Variables
		char *path = nullptr;
		double multiplier = 1;
		ege::fileProperties context;
		ege::COMPRESSION_METHOD compression_type = ege::COMPRESSION_METHOD::NO_COMPRESS;		

		// Functions
		inline bool checkfile(char* file);
		const char* strcomptype(ege::COMPRESSION_METHOD id);		
		ERR_STATUS compress(FILE* Src, FILE* Dest);
		ERR_STATUS decompress(FILE* Src, FILE* Dest);
		ERR_STATUS copy(char* pathSrc, char* pathDest);
		ERR_STATUS readHeader(char* pathSrc);
		void prepareHeader();
		ERR_STATUS writeHeader(char* pathDest);
		void configFromHeader();

#ifdef CRYPTOGRAPH_EGE
		size_t keylen = 0;
		Ipp8u* key = nullptr;
		IppHashAlgId hash_type = ippHashAlg_SHA512;		
		ege::CRYPTO_METHOD crypto_type = ege::CRYPTO_METHOD::NO_ENCRYPT;

		const char* strhashtype(IppHashAlgId id);
		const char* strcrypttype(ege::CRYPTO_METHOD id);
		ERR_STATUS encrypt(FILE* Src, FILE* Dest);
		ERR_STATUS decrypt(FILE* Src, FILE* Dest);
#endif // CRYPTOGRAPH_EGE
	
	};

	/******************************************* LZSS ******************************************/
	class LZSS_Comp
	{
	public:
		LZSS_Comp();
		ERR_STATUS encode(char* pathSrc, char* pathDest);
		ERR_STATUS decode(char* pathSrc, char* pathDest);
		ERR_STATUS encode(FILE *fsrc, FILE *fdst);
		ERR_STATUS decode(FILE *fsrc, FILE *fdst);
		~LZSS_Comp();

	private:
		IppLZSSState_8u *context = nullptr;
	};

	/******************************************* LZO *******************************************/
	class LZO_Comp 
	{
	public:
		LZO_Comp(ege::COMPRESSION_METHOD id);
		ERR_STATUS encode(char* pathSrc, char* pathDest);
		ERR_STATUS decode(char* pathSrc, char* pathDest);
		ERR_STATUS encode(FILE *fsrc, FILE *fdst);
		ERR_STATUS decode(FILE *fsrc, FILE *fdst);
		~LZO_Comp();

	private:
		IppLZOState_8u *context = nullptr;

	};

	/******************************************* LZ4 *******************************************/
	class LZ4_Comp
	{
	public:
		LZ4_Comp(ege::COMPRESSION_METHOD id);
		ERR_STATUS encode(char* pathSrc, char* pathDest);
		ERR_STATUS decode(char* pathSrc, char* pathDest);
		ERR_STATUS encode(FILE *fsrc, FILE *fdst);
		ERR_STATUS decode(FILE *fsrc, FILE *fdst);
		~LZ4_Comp();

	private:
		Ipp8u* hashTable = nullptr;
		Ipp8u* dict = nullptr; // Reserved
	};

	/*******************************************************************************************/
	/**************************************** Functions ****************************************/
	/*******************************************************************************************/

}