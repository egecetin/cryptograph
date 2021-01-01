#pragma once

#include "logger.h"
#include "cryptograph.h"

#include <omp.h>
#include <cstdio>
#include <chrono>
#include <cstdint>
#include <filesystem>

#define HEADER_SIZE			  74
#define BUFFER_SIZE		   65536	//  64 kB
#define COMP_BUFSIZ		  131072	// 128 kB
#define COMP_EXTEND			1024	//   1 kB
#define DESCRIPTOR_LENGTH	 644  

namespace ege {

	// #################################### Definitions #################################### //	
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
		LZ4_HC,			// High-compression mode (Reserved)
		COMPRESSION_MAX
	};
	
	struct fileProperties
	{
		uint64_t size;					// Original file size
		uint64_t c_size;				// Compressed size
		char filename[FILENAME_MAX];	// Filename includes relative directory and extension
		char extension[FILENAME_MAX];	// Extension of file
		char lastwrite[25];				// std::asctime has fixed 25 character
		uint8_t hashmethod;				// Hash method
		Ipp8u hashcode[MAX_HASH_LEN];	// Hash code
		uint64_t startIdx;				// Start index inside container
		uint64_t nIdx;					// Total number of indexes
	};

	class Filer
	{
	public:
		// ########### Variables ########### //
		volatile double progress = 0; // Between 0 - 1

		// ########### Functions ########### //
		Filer(std::string pathSrc = std::string());
		
		ERR_STATUS setPath(std::string pathSrc);
		ERR_STATUS ege::Filer::setTempPath(std::string pathTemp);
		ERR_STATUS pack(const char* pathDest, bool overwrite = false);
		ERR_STATUS unpack(const char* pathDest, bool overwrite = false);
		ERR_STATUS encrypt(FILE* Src, FILE* Dest, Ipp8u* hashcode, bool keyword);
		ERR_STATUS decrypt(FILE* Src, FILE* Dest, bool keyword);
		ERR_STATUS compress(FILE* Src, FILE* Dest);
		ERR_STATUS decompress(FILE* Src, FILE* Dest);

		ERR_STATUS setThreadNum(size_t n);
		size_t getThreadNum();

		// Compression functions
		ERR_STATUS setCompressionType(ege::COMPRESSION_METHOD id);
		ege::COMPRESSION_METHOD getCompressionType();
		
		// Encryption functions
		void setKey(Ipp8u* key, size_t keylen);
		ERR_STATUS setEncryptionMethod(ege::CRYPTO_METHOD id);
		ege::CRYPTO_METHOD getEncryptionMethod();
		
		// Hash functions
		ERR_STATUS setHashMethod(IppHashAlgId id);
		IppHashAlgId getHashMethod();

		~Filer();

	private:
		// ########### Variables ########### //
		size_t nThread = 1;							// Number of threads for pack/unpack

		std::string srcDir;							// Directory for processing
		std::string tempDir;						// Directory for temporarily use
		size_t nFiles = 0;							// Number of files given at path
		std::vector<ege::fileProperties> contexts;	// Identifiers of files

		Ipp8u* key = nullptr;						// Encryption key
		size_t keyLen = 0;							// Length of the key
		Ipp8u hashcode[MAX_HASH_LEN];				// Hash code

		IppHashAlgId hash_type = ippHashAlg_SHA512;										 // Type of hash
		ege::CRYPTO_METHOD crypto_type = ege::CRYPTO_METHOD::NO_ENCRYPT;				 // Type of encryption
		ege::COMPRESSION_METHOD compression_type = ege::COMPRESSION_METHOD::NO_COMPRESS; // Type of requested compression		

		// ########### Functions ########### //
		ERR_STATUS moveFile(std::string pathSrc, std::string pathDest, bool overwrite = false);
		ERR_STATUS copyFile(std::string pathSrc, std::string pathDest, bool overwrite = false, bool removeSrc = false);

		// Container
		ERR_STATUS readHeader(const char* pathSrc);
		ERR_STATUS writeHeader(const char* pathDest);
		ERR_STATUS prepareContext(std::filesystem::path pathSrc, ege::fileProperties &context);

		// Helper
		inline bool checkfile(std::string file);
		uint64_t readSize(std::filesystem::path file);
		char* readLastWrite(const char* file);
		size_t getNumFiles(std::filesystem::path path);
		inline void packContext(const fileProperties context, Ipp8u* packedBin);
	};

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

}