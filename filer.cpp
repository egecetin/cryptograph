#include "filer.h"

/** ##############################################################################################################
	Checks whether file exists
	Input;
		file	: File path
	Output;
		retval	: True if exists, false otherwise
*/
inline bool ege::Filer::checkfile(std::string file)
{
	return std::filesystem::exists(file);
}

/** ##############################################################################################################
	Gets the last write time of file
	Input;
		file	: File path
	Output;
		retval	: asctime formatted last access time
*/
char * ege::Filer::readLastWrite(const char* file)
{
	auto lasttime = std::filesystem::last_write_time(file);
	std::time_t cftime = lasttime.time_since_epoch().count();
	return std::asctime(std::localtime(&cftime));
}

/** ##############################################################################################################
	Gets the number of files
	Input;
		file	: Directory path
	Output;
		retval	: Total count of files
*/
size_t ege::Filer::getNumFiles(std::filesystem::path path)
{
	using fp = bool(*)(const std::filesystem::path&);
	return std::count_if(std::filesystem::recursive_directory_iterator(path), 
						std::filesystem::recursive_directory_iterator{}, 
						(fp)std::filesystem::is_regular_file);
}

inline void ege::Filer::packContext(const fileProperties context, Ipp8u* packedBin)
{

}

/** ##############################################################################################################
	Gets the file size
	Input;
		file	: File path
	Output;
		retval	: Size of file in bytes
*/
uint64_t ege::Filer::readSize(std::filesystem::path file)
{
	return std::filesystem::file_size(file);
}

/** ##############################################################################################################
	Compress an input file and write to destination. Does not write any information to header. For decompress all
	parameters should set manually.
	Input;
		Src		: Path of file which will be compressed
		Dest	: File path of write compressed data
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::compress(FILE* Src, FILE* Dest)
{
	switch (this->compression_type)
	{
	case ege::LZSS:
	{
		LZSS_Comp compressor;
		return compressor.encode(Src, Dest);
	}
	case ege::ZLIB_FAST:
		// Reserved
	case ege::ZLIB_AVERAGE:
		// Reserved
	case ege::ZLIB_SLOW:
		// Reserved
	case ege::LZO_FAST:
	{
		LZO_Comp compressor(ege::LZO_FAST);
		return compressor.encode(Src, Dest);
	}
	case ege::LZO_SLOW:
	{
		LZO_Comp compressor(ege::LZO_SLOW);
		return compressor.encode(Src, Dest);
	}
	case ege::LZ4:
	{
		LZ4_Comp compressor(ege::LZ4);
		return compressor.encode(Src, Dest);
	}
	case ege::LZ4_HC:
	{
		LZ4_Comp compressor(ege::LZ4_HC);
		return compressor.encode(Src, Dest);
	}
	default:
		return COMP_UNKNOWN_METHOD;
	}
}

/** ##############################################################################################################
	Decompress an input file and write to destination. Does not read any information from header. All parameters
	should set manually.
	Input;
		Src		: Path of file which will be decompressed
		Dest	: File path of write decompressed data
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::decompress(FILE* Src, FILE* Dest)
{
	switch (this->compression_type)
	{
	case ege::LZSS:
	{
		LZSS_Comp compressor;
		return compressor.decode(Src, Dest);
	}
	case ege::ZLIB_FAST:
		// Reserved
	case ege::ZLIB_AVERAGE:
		// Reserved
	case ege::ZLIB_SLOW:
		// Reserved
	case ege::LZO_FAST:
	{
		LZO_Comp compressor(ege::LZO_FAST);
		return compressor.decode(Src, Dest);
	}
	case ege::LZO_SLOW:
	{
		LZO_Comp compressor(ege::LZO_SLOW);
		return compressor.decode(Src, Dest);
	}
	case ege::LZ4:
	{
		LZ4_Comp compressor(ege::LZ4);
		return compressor.decode(Src, Dest);
	}
	case ege::LZ4_HC:
	{
		LZ4_Comp compressor(ege::LZ4_HC);
		return compressor.decode(Src, Dest);
	}
	default:
		return COMP_UNKNOWN_METHOD;
	}
}

/** ##############################################################################################################
	Sets the maximum thread count for packing/unpacking operations
	Input;
		n		: Number of threads
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::setThreadNum(size_t n)
{
	if (n > omp_get_max_threads())
		return TOO_MANY_THREADS;
	this->nThread = n;
	return NO_ERROR;
}

/** ##############################################################################################################
	Returns the maximum thread count for packing/unpacking operations
	Input;
	Output;
		retval	: Number of threads
*/
size_t ege::Filer::getThreadNum()
{
	return this->nThread;
}

/** ##############################################################################################################
	Prepare file related information. Compressed size, hashcode, startIdx and nIdx should be set after process.
	Input;
		pathSrc	: Path of file
	Output;
		context	: Information context of file
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::prepareContext(std::filesystem::path pathSrc, ege::fileProperties &context)
{
	std::string buff;

	// Write relative directory
	buff = std::filesystem::relative(pathSrc, this->srcDir).string();
	if (buff.length() > FILENAME_MAX)
		return OVER_FILENAME_LIMIT;
	memcpy(context.filename, buff.c_str(), buff.length());

	// Write extension
	buff = pathSrc.extension().string();
	if (buff.length() > FILENAME_MAX)
		return OVER_FILENAME_LIMIT;
	memcpy(context.extension, buff.c_str(), buff.length());

	memcpy(context.lastwrite, this->readLastWrite(pathSrc.string().c_str()), 25); // Last access
	context.size = this->readSize(pathSrc);		// Size of original file
	context.c_size = 0;							// Size of compressed file
	context.hashmethod = this->hash_type;		// Hash method
	memset(context.hashcode, 0, MAX_HASH_LEN);	// Reset hashcode
	context.startIdx = 0;						// Start position inside container
	context.nIdx = 0;							// Number of frames

	return NO_ERROR;
}

/** ##############################################################################################################
	Read unencrypted header
	Input;
		pathSrc : Path to container file
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::readHeader(const char *pathSrc)
{
	FILE *fptr = fopen(pathSrc, "rb");
	if (!fptr)
		return FILE_INPUT_OUTPUT_ERR;

	char buffer[5]; buffer[4] = '\0';
	size_t size = 0;

	fread(buffer, 4, 1, fptr);
	if (strcmp(buffer, "EGE!"))
	{
		fclose(fptr);
		return FILE_NOT_SUPPORTED;
	}

	uint8_t buff = 0;
	fread(&buff, sizeof(uint8_t), 1, fptr); // Read encryption method
	if (buff < ege::CRYPTO_METHOD::CRYPTO_METHOD_MAX)
		this->crypto_type = static_cast<ege::CRYPTO_METHOD>(buff);
	else
	{
		fclose(fptr);
		return CRYPT_UNKNOWN_METHOD;
	}

	fread(&buff, sizeof(uint8_t), 1, fptr); // Read hash method
	if (buff < ippHashAlg_MaxNo)
		this->hash_type = static_cast<IppHashAlgId>(buff);
	else
	{
		fclose(fptr);
		return HASH_UNKNOWN_METHOD;
	}

	fread(&(this->hashcode), sizeof(this->hashcode), 1, fptr);	// Read fullfile hash
	
	fread(buffer, 4, 1, fptr);
	if (strcmp(buffer, "END!"))
	{
		fclose(fptr);
		return FILE_NOT_SUPPORTED;
	}

	return NO_ERROR;
}

/** ##############################################################################################################
	Writes header information to file after encryption
	Input;
		pathDest: Path of output file
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::writeHeader(const char *pathDest)
{
	FILE *fptr = fopen(pathDest,"rb+");
	if (!fptr)
		return FILE_INPUT_OUTPUT_ERR;

	fwrite("EGE!", sizeof(char) * 4, 1, fptr);					// Write start keyword

	uint8_t buff = uint8_t(this->crypto_type);
	fwrite(&buff, sizeof(uint8_t), 1, fptr);					// Write encryption type
	buff = uint8_t(this->hash_type);
	fwrite(&buff, sizeof(uint8_t), 1, fptr);					// Write hash method
	fwrite(&(this->hashcode), sizeof(this->hashcode), 1, fptr); // Write hash of all file

	fwrite("END!", sizeof(char) * 4, 1, fptr);					// Write end keyword

	fclose(fptr);
	return NO_ERROR;
}

/** ##############################################################################################################
	Encrypts a file. Does not write any information to header. For decryption all parameters should set manually
	Input;
		Src		: Source file path
		Dest	: Destination file path
		keyword	: Flag for whether write keyword or not
	Output;
		hashcode: Hash of the file
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::encrypt(FILE* Src, FILE* Dest, Ipp8u* hashcode, bool keyword)
{
	size_t size;
	ERR_STATUS status = NO_ERROR;	
	ege::Hash_Coder hasher(this->hash_type);
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFFER_SIZE);
	Ipp8u *cipher = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFFER_SIZE);

	switch (this->crypto_type)
	{
	case ege::CRYPTO_METHOD::AES:
	{
		AES_Crypt cryptograph(this->key, this->keyLen);
		if (keyword)
		{
			if (status = cryptograph.encryptMessage(KNOWN_WORD, 40, cipher))
				return status;
			fwrite(cipher, 40, 1, Dest);
		}

		while (size = fread(buff, 1, BUFFER_SIZE, Src)) {
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			if (status = hasher.update(cipher, size))
				break;
			fwrite(cipher, size, 1, Dest);
		}
		break;
	}
	case ege::CRYPTO_METHOD::SMS4:
	{
		SMS4_Crypt cryptograph(this->key, this->keyLen);
		if (keyword)
		{
			if (status = cryptograph.encryptMessage(KNOWN_WORD, 40, cipher))
				return status;
			fwrite(cipher, 40, 1, Dest);
		}

		while (size = fread(buff, 1, BUFFER_SIZE, Src)) {
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			if (status = hasher.update(cipher, size))
				break;
			fwrite(cipher, size, 1, Dest);
		}
		break;
	}
	default:
		status = CRYPT_UNKNOWN_METHOD;
	}

	if (!status)
		status = hasher.getHash(hashcode);
		
	for (size_t i = 0; i < BUFFER_SIZE; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	return status;
}

/** ##############################################################################################################
	Decrypts a file. Does not read any information from header. All parameters should set manually.
	Input;
		Src		: Source file path
		Dest	: Destination file path
		hashcode: Hash of the file for check
		keyword	: Flag for whether write keyword or not
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::decrypt(FILE* Src, FILE* Dest, Ipp8u *hashcode, bool keyword)
{
	int size;
	ERR_STATUS status = NO_ERROR;
	ege::Hash_Coder hasher(this->hash_type);
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFFER_SIZE);
	Ipp8u *cipher = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFFER_SIZE);

	switch (this->crypto_type)
	{
	case ege::CRYPTO_METHOD::AES:
	{
		AES_Crypt cryptograph(this->key, this->keyLen);
		size = fread(cipher, 1, 40, Src);
		if (status = cryptograph.decryptMessage(cipher, buff, size))
			return status;
		if (strcmp((char*)buff, (char*)KNOWN_WORD))
			return CRYPT_PASSWORD_ERROR;

		while (size = fread(cipher, 1, BUFFER_SIZE, Src)) {
			if (status = hasher.update(cipher, size))
				break;
			if (status = cryptograph.decryptMessage(cipher, buff, size))
				break;
			fwrite(buff, size, 1, Dest);
		}
		break;
	}
	case ege::CRYPTO_METHOD::SMS4:
	{
		SMS4_Crypt cryptograph(this->key, this->keyLen);
		size = fread(cipher, 1, 40, Src);
		if (status = cryptograph.decryptMessage(cipher, buff, size))
			return status;
		if (strcmp((char*)buff, (char*)KNOWN_WORD))
			return CRYPT_PASSWORD_ERROR;

		while (size = fread(cipher, 1, BUFFER_SIZE, Src)) {
			if (status = hasher.update(cipher, size))
				break;
			if (status = cryptograph.decryptMessage(cipher, buff, size))
				break;
			fwrite(buff, size, 1, Dest);
		}
		break;
	}
	default:
		status = CRYPT_UNKNOWN_METHOD;
	}

	if (!status) {
		status = hasher.getHash(buff);
		if (!status && !hashcode) {
			if (memcmp(buff, hashcode, MAX_HASH_LEN))
				return HASH_CHECK_FAIL;
		}
	}
	for (size_t i = 0; i < BUFFER_SIZE; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	return status;
}

/** ##############################################################################################################
	Constructor
*/
ege::Filer::Filer(std::string pathSrc)
{
	this->srcDir = pathSrc;
}

/** ##############################################################################################################
	Set path of class
	Input;
		pathSrc	: Path to process files
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::setPath(std::string pathSrc)
{
	if (this->checkfile(pathSrc)) {
		this->srcDir = pathSrc;
		return NO_ERROR;
	}
	else
		return FILE_NOT_EXIST;
}

/** ##############################################################################################################
	(Optional) Sets the temporary working directory
	Input;
		pathTemp: Directory to use temporarily
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::setTempPath(std::string pathTemp)
{
	if (!std::filesystem::is_directory(pathTemp))
		return NOT_A_DIRECTORY;

	this->tempDir = pathTemp;
	return NO_ERROR;
}

/** ##############################################################################################################
	Move a file
	Input;
		pathSrc		: Path of file which will be copied
		pathDest	: Path to copy file
		overwrite	: If it is true destination file will be overwrited
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::moveFile(std::string pathSrc, std::string pathDest, bool overwrite = false)
{
	if (pathSrc.empty())
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	pathSrc[0] == pathDest[0] ? rename(pathSrc.c_str(), pathDest.c_str()) : this->copyFile(pathSrc, pathDest, overwrite, true);
	
	return NO_ERROR;
}

/** ##############################################################################################################
	Copy a file
	Input;
		pathSrc		: Path of file which will be copied
		pathDest	: Path to copy file
		overwrite	: If it is true destination file will be overwrited
		removeSrc	: If it is true source file will be removed after copy operation
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::copyFile(std::string pathSrc, std::string pathDest, bool overwrite = false, bool removeSrc = false)
{
	// Check existance
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	
	size_t size;
	char buf[BUFFER_SIZE];

	// Open files
	FILE *src = fopen(pathSrc.c_str(), "rb");
	FILE *dest = fopen(pathDest.c_str(), "wb");
	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		return FILE_INPUT_OUTPUT_ERR;
	}

	// Copy
	while ((size = fread(buf, 1, BUFFER_SIZE, src))) {
		fwrite(buf, size, 1, dest);
	}

	// Close files
	fclose(src);
	fclose(dest);

	// Remove src file is requested
	if (removeSrc)
		std::filesystem::remove(pathSrc);

	return NO_ERROR;
}

/** ##############################################################################################################
	First compress all files independently and hash, then encrypt full file (reset ctr for every file) and hash
	Input;
		pathDest	: Path to output file
		overwrite	: If it is true destination file will be overwrited
	Output;
		retval	: Returns 0 on success
*/
ERR_STATUS ege::Filer::pack(const char *pathDest, bool overwrite)
{
	// Check variables
	if (this->srcDir.empty())
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	if (!(this->crypto_type) && !(this->key))
		return CRYPT_KEY_NOT_SET;

	uint64_t pos = 0;
	ERR_STATUS status = NO_ERROR;
	std::vector<char[FILENAME_MAX]> tempNames;

	// Set variables
	this->nFiles = this->getNumFiles(this->srcDir);
	this->contexts.reserve(this->nFiles);
	tempNames.reserve(this->nFiles);

	omp_set_num_threads(this->nThread);

	// Prepare file list
	std::vector<std::string> fileNames;
	fileNames.reserve(this->nFiles);
	if (std::filesystem::is_directory(this->srcDir))
	{
		for (const auto &entry : std::filesystem::recursive_directory_iterator(this->srcDir))
			fileNames.push_back(entry.path().string());
	}
	else
		fileNames.push_back(this->srcDir);

	// Compress all files and hash
	#pragma omp parallel for
	for (const auto &entry : fileNames)
	{
		if (std::filesystem::is_directory(entry))
			continue;

		ERR_STATUS status_local = NO_ERROR;
		ege::fileProperties context;
		Ipp8u hash[MAX_HASH_LEN];
		char tempname[FILENAME_MAX];

		// Prepare context information
		if ((status_local = prepareContext(entry, context)))
		{
			#pragma omp critical
			status = status_local;
		}
			
		// Compress if requested
		if (this->compression_type)
		{
			tmpnam(tempname);

			FILE *fSrc = fopen(entry.c_str(), "rb");
			FILE *fDest = fopen(tempname, "wb");
			if (!(fSrc && fDest))
			{
				fclose(fSrc);
				fclose(fDest);
				#pragma omp critical
				status = FILE_INPUT_OUTPUT_ERR;
			}
			status_local = this->compress(fSrc, fDest);
			fclose(fSrc);
			fclose(fDest);
			if (status_local)
			{
				#pragma omp critical
				status = status_local;
			}
		}
		else // Set source filename to tempname
			memcpy(tempname, entry.c_str(), entry.length());

		// Hash
		FILE *fPtr = fopen(tempname, "rb");
		ege::Hash_Coder hasher(this->hash_type);
		status_local = hasher.calcFileHash(fPtr, hash);
		fclose(fPtr);

		// Set last variables
		memcpy(context.hashcode, hash, MAX_HASH_LEN);
		context.c_size = this->readSize(tempname);
		context.nIdx = uint64_t(context.c_size / BUFFER_SIZE + 1);

		// Push to vector
		#pragma omp critical
		{
			context.startIdx = pos;					// Set start position
			pos += context.nIdx;					// Move position indicator
			tempNames.push_back(tempname);			// Record tempfile name
			this->contexts.push_back(context);		// Record context

			this->progress += 0.5 / this->nFiles;
		}
	}
		
	if (status)
		goto cleanup;

	// Sort contexts to ensure order
	std::sort(contexts.begin(), contexts.end(), [](const ege::fileProperties &left, const ege::fileProperties &right) {
		return left.startIdx < right.startIdx;
	});

	// Pass file header
	FILE *fDest = fopen(pathDest, "wb");
	char nullBuffer[HEADER_SIZE] = { '\0' };
	fwrite(nullBuffer, sizeof(char), HEADER_SIZE, fDest);

	// Start encryption and concat
	ege::Hash_Coder hasher(this->hash_type);
	switch (this->crypto_type)
	{
	case ege::CRYPTO_METHOD::NO_ENCRYPT: // Only concat files
	{
		Ipp8u buff[BUFFER_SIZE];
		size_t sizeBuff = 0;

		// First encrypt number of files
		memcpy(buff, &(this->nFiles), sizeof(this->nFiles));
		if ((status = hasher.update(buff, sizeof(this->nFiles))))
			goto cleanup;
		fwrite(buff, sizeof(this->nFiles), 1, fDest);

		// Encrypt context information and write
		for (const auto &entry : this->contexts)
		{
			Ipp8u contextBin[DESCRIPTOR_LENGTH];
			this->packContext(entry, contextBin);

			if ((status = hasher.update(contextBin, sizeof(contextBin))))
				goto cleanup;
			fwrite(contextBin, sizeof(contextBin), 1, fDest);
		}

		// Encrypt and concat files
		for (const auto &entry : tempNames)
		{
			size_t size = 0;
			FILE *fptr = fopen(entry, "rb");

			while (size = fread(buff, 1, BUFFER_SIZE, fptr)) {
				if (status = hasher.update(buff, size))
					break;
				fwrite(buff, size, 1, fDest);
			}
			fclose(fptr);

			this->progress += 0.5 / this->nFiles;
		}
		break;
	}
	case ege::CRYPTO_METHOD::AES:
	{
		ege::AES_Crypt crypt(this->key, this->keyLen);
		Ipp8u buff[BUFFER_SIZE], cipher[BUFFER_SIZE];
		size_t sizeBuff = 0;

		// First write keyword for password check
		if (status = crypt.encryptMessage(KNOWN_WORD, 40, cipher))
			goto cleanup;
		fwrite(cipher, 40, 1, fDest);

		// First encrypt number of files
		memcpy(buff, &(this->nFiles), sizeof(this->nFiles));
		if((status = crypt.encryptMessage(buff, sizeof(this->nFiles), cipher)))
			goto cleanup;
		if ((status = hasher.update(buff, sizeof(this->nFiles))))
			goto cleanup;
		fwrite(cipher, sizeof(this->nFiles), 1, fDest);

		// Encrypt context information and write
		for (const auto &entry : this->contexts)
		{
			Ipp8u contextBin[DESCRIPTOR_LENGTH];
			this->packContext(entry, contextBin);

			if ((status = crypt.encryptMessage(contextBin, sizeof(contextBin), cipher)))
				goto cleanup;
			if ((status = hasher.update(cipher, sizeof(contextBin))))
				goto cleanup;
			fwrite(cipher, sizeof(contextBin), 1, fDest);
		}

		// Encrypt and concat files
		for (const auto &entry : tempNames)
		{
			size_t size = 0;
			FILE *fptr = fopen(entry, "rb");
			crypt.resetCtr();
				
			while (size = fread(buff, 1, BUFFER_SIZE, fptr)) {
				if (status = crypt.encryptMessage(buff, size, cipher))
					break;
				if (status = hasher.update(cipher, size))
					break;
				fwrite(cipher, size, 1, fDest);
			}
			fclose(fptr);

			this->progress += 0.5 / this->nFiles;
		}
		break;
	}
	case ege::CRYPTO_METHOD::SMS4:
	{
		ege::SMS4_Crypt crypt(this->key, this->keyLen);
		Ipp8u buff[BUFFER_SIZE], cipher[BUFFER_SIZE];
		size_t sizeBuff = 0;

		// First write keyword for password check
		if (status = crypt.encryptMessage(KNOWN_WORD, 40, cipher))
			goto cleanup;
		fwrite(cipher, 40, 1, fDest);

		// First encrypt number of files
		memcpy(buff, &(this->nFiles), sizeof(this->nFiles));
		if ((status = crypt.encryptMessage(buff, sizeof(this->nFiles), cipher)))
			goto cleanup;
		fwrite(cipher, sizeof(this->nFiles), 1, fDest);

		// Encrypt context information and write
		for (const auto &entry : this->contexts)
		{
			Ipp8u contextBin[DESCRIPTOR_LENGTH];
			this->packContext(entry, contextBin);

			if ((status = crypt.encryptMessage(contextBin, sizeof(contextBin), cipher)))
				goto cleanup;
			fwrite(cipher, sizeof(contextBin), 1, fDest);
		}

		// Encrypt and concat files
		for (const auto &entry : tempNames)
		{
			size_t size = 0;
			FILE *fptr = fopen(entry, "rb");

			while (size = fread(buff, 1, BUFFER_SIZE, fptr)) {
				if (status = crypt.encryptMessage(buff, size, cipher))
					break;
				if (status = hasher.update(cipher, size))
					break;
				fwrite(cipher, size, 1, fDest);
			}

			this->progress += 0.5 / this->nFiles;
		}
		break;
	}
	default:
	{
		status = CRYPT_UNKNOWN_METHOD;
		goto cleanup;
	}
	}

	if (status)
		goto cleanup;

	// Set hash code and write header
	if (status = hasher.getHash(this->hashcode))
		goto cleanup;
	this->writeHeader(pathDest);

cleanup:
	this->progress = 1;
	
	if (status)
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();

	if (this->compression_type)
	{
		for (const auto &entry : tempNames)
			std::filesystem::remove(entry);
	}
	
	return status;
}


ERR_STATUS ege::Filer::unpack(char * pathDest, bool overwrite)
{
	FILE *fsrc, *fdst;
	ERR_STATUS status = NO_ERROR;
	char tempname[FILENAME_MAX]; tmpnam(tempname);

	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	this->progress = 0;
	if (status = this->readHeader(this->path) != NO_ERROR)
		return status;
	this->configFromHeader();
	
	fsrc = fopen(this->path, "rb");
	if (this->context.compression != NO_COMPRESS && !this->context.crypto_check) { // Only compress	
		fdst = fopen(pathDest, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 1;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);		
		if (status = this->decompress(fsrc, fdst))
			goto cleanup;
	}
	else if (this->context.compression == NO_COMPRESS && this->context.crypto_check) { // Only crypto
		fdst = fopen(pathDest, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 1;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);		
		if (status = this->decrypt(fsrc, fdst))
			goto cleanup;
		return CRYPT_NOT_SUPPORTED;
	}
	else if (this->context.compression != NO_COMPRESS && this->context.crypto_check) { // Both compress + crypto
		while (std::filesystem::exists(tempname)) // For ensure thread safety
			tmpnam(tempname);
		fdst = fopen(tempname, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 0.5;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);
		if (status = this->decrypt(fsrc, fdst))
			goto cleanup;
		this->progress = 50;

		fclose(fsrc); fsrc = fopen(tempname, "rb");
		fclose(fdst); fdst = fopen(pathDest, "wb");

		if (status = this->decompress(fsrc, fdst))
			goto cleanup;
		return CRYPT_NOT_SUPPORTED;
	}

cleanup:
	this->progress = 100;
	fclose(fsrc); fclose(fdst);

	if (status)
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();

	std::filesystem::exists(tempname) ? std::filesystem::remove(tempname) : void();

	return status;
}

/** ##############################################################################################################
	Sets the compression type
	Input;
		id	: Compression type
	Output;
*/
ERR_STATUS ege::Filer::setCompressionType(ege::COMPRESSION_METHOD id)
{
	if (id >= ege::COMPRESSION_METHOD::COMPRESSION_MAX)
		return COMP_UNKNOWN_METHOD;
	this->compression_type = id;
	return NO_ERROR;
}

/** ##############################################################################################################
	Returns the compression type
	Input;
	Output;
		retval	: Compression type
*/
ege::COMPRESSION_METHOD ege::Filer::getCompressionType()
{
	return this->compression_type;
}

/** ##############################################################################################################
	Sets the encryption key
	Input;
		key		: Pointer to a symmetric key
		keylen	: Length of key in bits
	Output;
*/
void ege::Filer::setKey(Ipp8u * key, size_t keylen)
{
	if (!this->key)
		this->key = (Ipp8u*)malloc(sizeof(Ipp8u) * keylen / 8);
	else
		this->key = (Ipp8u*)realloc(this->key, keylen / 8);
	for (size_t i = 0; i < keylen / 8; ++i)
		this->key[i] = 0;
	memcpy(this->key, key, sizeof(Ipp8u)*keylen);
	this->keyLen = keylen;
}

/** ##############################################################################################################
	Sets the encryption method
	Input;
		id	: Encryption type
	Output;
*/
ERR_STATUS ege::Filer::setEncryptionMethod(ege::CRYPTO_METHOD id)
{
	if (id >= ege::CRYPTO_METHOD::CRYPTO_METHOD_MAX)
		return CRYPT_UNKNOWN_METHOD;
	this->crypto_type = id;
	return NO_ERROR;
}

/** ##############################################################################################################
	Returns the encryption method
	Input;
	Output;
		retval	: Encryption type
*/
ege::CRYPTO_METHOD ege::Filer::getEncryptionMethod()
{
	return this->crypto_type;
}

/** ##############################################################################################################
	Sets the hash method
	Input;
		id	: Hash method
	Output;
*/
ERR_STATUS ege::Filer::setHashMethod(IppHashAlgId id)
{
	if (id >= ippHashAlg_MaxNo)
		return HASH_UNKNOWN_METHOD;
	this->hash_type = id;
	return NO_ERROR;
}

/** ##############################################################################################################
	Returns the hash method
	Input;
	Output;
		retval	: Hash method
*/
IppHashAlgId ege::Filer::getHashMethod()
{
	return this->hash_type;
}

/** ##############################################################################################################
	Deconstructor
*/
ege::Filer::~Filer()
{
	memset(this->key, 0, this->keyLen);
	free(this->key);
}

ege::LZSS_Comp::LZSS_Comp()
{
	int ctxSize = 0;

	ippsLZSSGetSize_8u(&ctxSize);
	this->context = (IppLZSSState_8u*)new Ipp8u[ctxSize];
}

ERR_STATUS ege::LZSS_Comp::encode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}
	status = this->encode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZSS_Comp::decode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	status = this->decode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZSS_Comp::encode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;

	if (status = ippsEncodeLZSSInit_8u(this->context))
		return status;

	int size_buff, size_out;
	Ipp8u *buff_org = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ), *buff = buff_org;
	Ipp8u *out_org = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ + COMP_EXTEND), *out = out_org;

	size_out = COMP_BUFSIZ + COMP_EXTEND;
	size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
	if (size_buff) {
		while (true) {
			status = ippsEncodeLZSS_8u(&buff, &size_buff, &out, &size_out, this->context);
			if (status == ippStsDstSizeLessExpected) {
				fwrite(out_org, COMP_BUFSIZ + COMP_EXTEND - size_out, 1, fdst);
				out = out_org;
				size_out = COMP_BUFSIZ + COMP_EXTEND;
			}
			else if (status == NO_ERROR) {
				fwrite(out_org, COMP_BUFSIZ + COMP_EXTEND - size_out, 1, fdst);
				size_buff = 0;
				size_out = COMP_BUFSIZ + COMP_EXTEND;
				buff = buff_org;
				out = out_org;
				size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
				if (!size_buff)
					break;
			}
			else
				break;
		}
	}

	if (!status) { // Last bits
		status = ippsEncodeLZSSFlush_8u(&out, &size_out, this->context);
		fwrite(out_org, COMP_BUFSIZ + COMP_EXTEND - size_out, 1, fdst);
	}

	free(buff_org);
	free(out_org);

	return status;
}

ERR_STATUS ege::LZSS_Comp::decode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;

	if (status = ippsDecodeLZSSInit_8u(this->context))
		return status;

	int size_buff, size_out;
	Ipp8u *buff_org = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ), *buff = buff_org;
	Ipp8u *out_org = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ * 4), *out = out_org;

	size_out = COMP_BUFSIZ * 4;
	size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
	if (size_buff) {
		while (true) {
			status = ippsDecodeLZSS_8u(&buff, &size_buff, &out, &size_out, this->context);
			if (status == ippStsDstSizeLessExpected) {
				fwrite(out_org, COMP_BUFSIZ * 4 - size_out, 1, fdst);
				out = out_org;
				size_out = COMP_BUFSIZ * 4;
			}
			else if (status == NO_ERROR) {
				fwrite(out_org, COMP_BUFSIZ * 4 - size_out, 1, fdst);
				size_buff = COMP_BUFSIZ;
				size_out = COMP_BUFSIZ * 4;
				buff = buff_org;
				out = out_org;
				size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
				if (!size_buff)
					break;
			}
			else
				break;
		}
	}

	free(buff_org);
	free(out_org);

	return status;
}

ege::LZSS_Comp::~LZSS_Comp()
{
	delete[](Ipp8u*)this->context;
}

ege::LZO_Comp::LZO_Comp(ege::COMPRESSION_METHOD id)
{
	Ipp32u ctxSize = 0;
	
	switch (id)
	{
	case ege::LZO_FAST:
		ippsEncodeLZOGetSize(IppLZO1X1ST, 0, &ctxSize);
		this->context = (IppLZOState_8u*)new Ipp8u[ctxSize];
		ippsEncodeLZOInit_8u(IppLZO1X1ST, 0, this->context);
		break;
	case ege::LZO_SLOW:
		ippsEncodeLZOGetSize(IppLZO1XST, 0, &ctxSize);
		this->context = (IppLZOState_8u*)new Ipp8u[ctxSize];
		ippsEncodeLZOInit_8u(IppLZO1X1ST, 0, this->context);
		break;
	}
}

ERR_STATUS ege::LZO_Comp::encode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	status = this->encode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZO_Comp::decode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}
	status = this->decode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZO_Comp::encode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;
	Ipp32u size_buff, size_out;

	if (!this->context)
		return COMP_CLASS_BROKEN;

	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ);
	Ipp8u *out = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ + COMP_EXTEND);

	size_buff = COMP_BUFSIZ, size_out = COMP_BUFSIZ + COMP_EXTEND;
	while (size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc)) {
		if (status = ippsEncodeLZO_8u(buff, size_buff, out, &size_out, this->context))
			break;
		fwrite(out, size_out, 1, fdst);
		size_out = COMP_BUFSIZ + COMP_EXTEND;
	}

	free(buff);
	free(out);

	return status;
}

ERR_STATUS ege::LZO_Comp::decode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;
	Ipp32u size_buff, size_out;
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ);
	Ipp8u *out = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ * 4);

	size_buff = COMP_BUFSIZ, size_out = COMP_BUFSIZ * 4;

	size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
	if (size_buff) {
		while (true)
		{
			status = ippsDecodeLZOSafe_8u(buff, size_buff, out, &size_out);
			if (status == ippStsDstSizeLessExpected) {
				out = (Ipp8u*)realloc(out, sizeof(Ipp8u)*size_out * 2);
				size_out *= 2;
			}
			else if (status == NO_ERROR) {
				fwrite(out, size_out, 1, fdst);
				size_out = COMP_BUFSIZ * 4;
				size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
				if (!size_buff)
					break;
			}
			else
				break;
		}
	}

	free(buff);
	free(out);

	return status;
}

ege::LZO_Comp::~LZO_Comp()
{
	delete[](Ipp8u*)this->context;
}

ege::LZ4_Comp::LZ4_Comp(ege::COMPRESSION_METHOD id)
{
	int ctxSize;

	switch (id)
	{
	case ege::LZ4_HC:
		// Reserved
	default:
		ippsEncodeLZ4HashTableGetSize_8u(&ctxSize);
		this->hashTable = new Ipp8u[ctxSize];
		ippsEncodeLZ4HashTableInit_8u(this->hashTable, ctxSize);
	}
}

ERR_STATUS ege::LZ4_Comp::encode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;
	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	status = this->encode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZ4_Comp::decode(char * pathSrc, char * pathDest)
{
	ERR_STATUS status = NO_ERROR;

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::filesystem::exists(pathDest) ? std::filesystem::remove(pathDest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	status = this->decode(src, dest);

	fclose(src);
	fclose(dest);

	return status;
}

ERR_STATUS ege::LZ4_Comp::encode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;
	int size_buff, size_out;
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ);
	Ipp8u *out = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ + COMP_EXTEND);

	size_buff = COMP_BUFSIZ, size_out = COMP_BUFSIZ + COMP_EXTEND;
	while (size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc)) {
		if (status = ippsEncodeLZ4_8u(buff, size_buff, out, &size_out, this->hashTable))
			break;
		fwrite(out, size_out, 1, fdst);
		size_out = COMP_BUFSIZ + COMP_EXTEND;
	}

	free(buff);
	free(out);

	return status;
}

ERR_STATUS ege::LZ4_Comp::decode(FILE * fsrc, FILE * fdst)
{
	ERR_STATUS status = NO_ERROR;
	int size_buff, size_out;
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ);
	Ipp8u *out = (Ipp8u*)malloc(sizeof(Ipp8u)*COMP_BUFSIZ * 4);

	size_out = COMP_BUFSIZ * 4;
	size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
	if (size_buff) {
		while (true)
		{
			status = ippsDecodeLZ4_8u(buff, size_buff, out, &size_out);
			if (status == ippStsDstSizeLessExpected) {
				out = (Ipp8u*)realloc(out, sizeof(Ipp8u)*size_out * 2);
				size_out *= 2;
			}
			else if (status == NO_ERROR) {
				fwrite(out, size_out, 1, fdst);
				size_out = COMP_BUFSIZ * 4;
				size_buff = fread(buff, 1, COMP_BUFSIZ, fsrc);
				if (!size_buff)
					break;
			}
			else
				break;
		}
	}

	free(buff);
	free(out);

	return status;
}

ege::LZ4_Comp::~LZ4_Comp()
{
	delete[](Ipp8u*)this->hashTable;
}
