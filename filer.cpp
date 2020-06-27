#include "filer.h"


inline bool ege::Filer::checkfile(char * file)
{
	return std::experimental::filesystem::exists(file);
}

char * ege::Filer::readLastWrite(char* file)
{
	auto lasttime = std::experimental::filesystem::last_write_time(file);
	std::time_t cftime = decltype(lasttime)::clock::to_time_t(lasttime);
	return std::asctime(std::localtime(&cftime));
}

int64_t ege::Filer::readSize(char* file)
{
	return std::experimental::filesystem::file_size(file);
}

const char * ege::Filer::strcomptype(ege::COMPRESSION_METHOD id)
{
	switch (id)
	{
	case ege::COMPRESSION_METHOD::NO_COMPRESS:
		return "No compression";
	default:
		return "Unknown compression code.";
	}
}

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
		LZO_Comp compressor(ege::LZO_FAST);
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
		LZO_Comp compressor(ege::LZO_FAST);
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

ERR_STATUS ege::Filer::copy(char * pathSrc, char * pathDest)
{
	size_t size;
	char buf[BUFFER_SIZE];

	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");
	if (!(src && dest))
		return FILE_INPUT_OUTPUT_ERR;

	while (size = fread(buf, 1, BUFFER_SIZE, src)) {
		fwrite(buf, size, 1, dest);
	}

	fclose(src);
	fclose(dest);

	return NO_ERROR;
}

void ege::Filer::prepareHeader()
{
	std::experimental::filesystem::path path = this->path;

	this->context.size = this->readSize(this->path);
	strcpy(this->context.filename, path.filename().string().c_str());
	strcpy(this->context.extension, path.extension().string().c_str());
	strcpy(this->context.lastwrite, this->readLastWrite(this->path));
	this->context.compression = this->getCompressionType();
#ifdef CRYPTOGRAPH_EGE	
	this->context.crypto = this->getEncryptionMethod();
	this->context.crypto == ege::CRYPTO_METHOD::NO_ENCRYPT ? this->context.crypto_check = 0 : this->context.crypto_check = 1;
	this->context.hashmethod = this->getHashMethod();
#else
	this->context.crypto_check = 0;
#endif // CRYPTOGRAPH_EGE

}

ERR_STATUS ege::Filer::readHeader(char * pathSrc)
{
	FILE *fptr = fopen(pathSrc, "rb");
	if (!fptr)
		return FILE_INPUT_OUTPUT_ERR;

	char buffer[5]; buffer[4] = '\0';
	size_t size = 0;

	fread(buffer, 4, 1, fptr);
	if (strcmp(buffer, "EGE!"))
		return FILE_NOT_SUPPORTED;
	fread(&size, sizeof(size_t), 1, fptr); // Read size

	if (size == sizeof(ege::fileProperties)) { // HOST + CLIENT EQUAL
		fread(&this->context, sizeof(ege::fileProperties), 1, fptr);
		
		fread(buffer, 4, 1, fptr);
		if (strcmp(buffer, "END!"))
			return FILE_NOT_SUPPORTED;
	}
#ifdef CRYPTOGRAPH_EGE
	else if (size < sizeof(ege::fileProperties)) { // HOST NORMAL + CLIENT CRYPT
		fread(&this->context, size, 1, fptr);
		
		fread(buffer, 5, 1, fptr);
		if (strcmp(buffer, "END!"))
			return FILE_NOT_SUPPORTED;
		
		this->context.crypto = ege::CRYPTO_METHOD::NO_ENCRYPT;
		this->context.hashmethod = ippHashAlg_Unknown;
	}
#endif // CRYPTOGRAPH_EGE
	else if (size > sizeof(ege::fileProperties)) { // HOST CRYPT + CLIENT NORMAL
		fread(&this->context, sizeof(ege::fileProperties), 1, fptr);
		
		fread(buffer, 5, 1, fptr);
		if (strcmp(buffer, "END!"))
			return FILE_NOT_SUPPORTED;		
		if (this->context.crypto_check)
			return CRYPT_NOT_SUPPORTED;
	}

	return NO_ERROR;
}

ERR_STATUS ege::Filer::writeHeader(char * pathDest)
{
	FILE *fptr = fopen(pathDest,"rb+");
	if (!fptr)
		return FILE_INPUT_OUTPUT_ERR;

	size_t size = sizeof(ege::fileProperties);

	fwrite("EGE!", sizeof(char) * 4, 1, fptr);	
	fwrite(&size, sizeof(size_t), 1, fptr);
	fwrite(&this->context, sizeof(this->context), 1, fptr);
	fwrite("END!", sizeof(char) * 4, 1, fptr);
	fclose(fptr);

	return NO_ERROR;
}

void ege::Filer::configFromHeader()
{
	this->setCompressionType(this->context.compression);
#ifdef CRYPTOGRAPH_EGE
	this->setEncryptionMethod(this->context.crypto);
	this->setHashMethod(this->context.hashmethod);
#endif // CRYPTOGRAPH_EGE
}

#ifdef CRYPTOGRAPH_EGE
const char * ege::Filer::strhashtype(IppHashAlgId id)
{
	switch (id)
	{
	case ippHashAlg_Unknown:
		return "Unknown hash code.";
	case ippHashAlg_SHA1:
		return "SHA-1";
	case ippHashAlg_SHA256:
		return "SHA-256";
	case ippHashAlg_SHA224:
		return "SHA-224";
	case ippHashAlg_SHA512:
		return "SHA-512";
	case ippHashAlg_SHA384:
		return "SHA-384";
	case ippHashAlg_MD5:
		return "MD5";
	case ippHashAlg_SM3:
		return "SM3";
	case ippHashAlg_SHA512_224:
		return "SHA-512/224";
	case ippHashAlg_SHA512_256:
		return "SHA-512/256";
	default:
		return "Unknown hash code.";
	}
}

const char * ege::Filer::strcrypttype(ege::CRYPTO_METHOD id)
{
	// Always return 5 character ('CODE' + '\0')
	switch (id)
	{
	case ege::CRYPTO_METHOD::NO_ENCRYPT:
		return "    ";
	case ege::CRYPTO_METHOD::AES:
		return " AES";
	case ege::CRYPTO_METHOD::SMS4:
		return "SMS4";
	case ege::CRYPTO_METHOD::RSA:
		return " RSA";
	case ege::CRYPTO_METHOD::ECCP:
		return "ECCP";
	default:
		return "----";
	}
}
ERR_STATUS ege::Filer::encrypt(FILE* Src, FILE* Dest)
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
		AES_Crypt cryptograph(this->key);
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
		SMS4_Crypt cryptograph(this->key);
		while (size = fread(buff, 1, BUFFER_SIZE, Src)) {
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			if (status = hasher.update(cipher, size))
				break;
			fwrite(cipher, size, 1, Dest);
		}
		break;
	}
	case ege::CRYPTO_METHOD::RSA:
		// Reserved
	case ege::CRYPTO_METHOD::ECCP:
		// Reserved
	default:
		status = CRYPT_UNKNOWN_METHOD;
	}

	if (!status)
		status = hasher.getHash(this->context.hashcode);
		
	for (size_t i = 0; i < BUFFER_SIZE; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	return status;
}
ERR_STATUS ege::Filer::decrypt(FILE* Src, FILE* Dest)
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
		AES_Crypt cryptograph(this->key);
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
		SMS4_Crypt cryptograph(this->key);
		while (size = fread(cipher, 1, BUFFER_SIZE, Src)) {
			if (status = hasher.update(cipher, size))
				break;
			if (status = cryptograph.decryptMessage(cipher, buff, size))
				break;
			fwrite(buff, size, 1, Dest);
		}
		break;
	}
	case ege::CRYPTO_METHOD::RSA:
		// Reserved
	case ege::CRYPTO_METHOD::ECCP:
		// Reserved
	default:
		status = CRYPT_UNKNOWN_METHOD;
	}

	if (!status) {
		status = hasher.getHash(buff);
		if (!status) {
			if (memcmp(buff, this->context.hashcode, 64))
				return HASH_CHECK_FAIL;
		}
	}
	for (size_t i = 0; i < BUFFER_SIZE; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	return status;
}
#endif

ege::Filer::Filer(char * pathSrc)
{
	if (pathSrc) {
		this->path = (char*)malloc(sizeof(char)*FILENAME_MAX);
		this->setPath(pathSrc);
	}
}

ERR_STATUS ege::Filer::setPath(char * pathSrc)
{
	if (!this->path)
		this->path = new char[FILENAME_MAX];
	if (strlen(pathSrc) < FILENAME_MAX && pathSrc) {
		if (this->checkfile(pathSrc)) {
			strcpy(this->path, pathSrc);
			return NO_ERROR;
		}
		else
			return FILE_NOT_EXIST;
	}
	else if (pathSrc)
		return OVER_FILENAME_LIMIT;
	else
		return FILE_NOT_SET;
}

ERR_STATUS ege::Filer::moveFile(char * pathDest, bool overwrite)
{
	if (this->path)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	this->path[0] == pathDest[0] ? rename(this->path, pathDest) : this->copy(this->path, pathDest);
	
	return NO_ERROR;
}

ERR_STATUS ege::Filer::copyFile(char * pathDest, bool overwrite)
{
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	return this->copy(this->path, pathDest);
}

ERR_STATUS ege::Filer::pack(char * pathDest, bool overwrite)
{
	FILE *fsrc, *fdst;
	ERR_STATUS status = NO_ERROR;
	char tempname[FILENAME_MAX]; tmpnam(tempname);

	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	
	this->progress = 0;
	this->prepareHeader();	

	fsrc = fopen(this->path, "rb");
	if (this->context.compression != NO_COMPRESS && !this->context.crypto_check) {	// Only compress	
		fdst = fopen(pathDest, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 2;
		fwrite("0", sizeof(ege::fileProperties) + 8 + sizeof(size_t), 1, fdst);		// Write random memory
		if (status = this->compress(fsrc, fdst))
			goto cleanup;
	}
	else if (this->context.compression == NO_COMPRESS  && this->context.crypto_check) { // Only crypto
	#ifdef CRYPTOGRAPH_EGE
		fdst = fopen(pathDest, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 2;
		fwrite("0", 1, sizeof(ege::fileProperties) + 8 + sizeof(size_t), fdst);		
		if (status = this->encrypt(fsrc, fdst))
			goto cleanup;
	#else
		return CRYPT_NOT_SUPPORTED;
	#endif // CRYPTOGRAPH_EGE
	}
	else if (this->context.compression != NO_COMPRESS && this->context.crypto_check) { // Both compress + crypto
	#ifdef CRYPTOGRAPH_EGE
		while (std::experimental::filesystem::exists(tempname)) // For ensure thread safety
			tmpnam(tempname);
		fdst = fopen(tempname, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 1;

		if (status = this->compress(fsrc, fdst))
			goto cleanup;
		this->progress = 50;

		fclose(fsrc); fsrc = fopen(tempname, "rb");
		fclose(fdst); fdst = fopen(pathDest, "wb");

		fwrite("0", 1, sizeof(ege::fileProperties) + 8 + sizeof(size_t), fdst);
		if (status = this->encrypt(fsrc, fdst))
			goto cleanup;
	#else
		return CRYPT_NOT_SUPPORTED;
	#endif // CRYPTOGRAPH_EGE
	}
	else
		status = UNKNOWN_ERROR;

cleanup:
	this->progress = 100;
	fclose(fsrc); fclose(fdst);
	
	if (!status)
		this->writeHeader(pathDest);
	else
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();

	std::experimental::filesystem::exists(tempname) ? std::experimental::filesystem::remove(tempname) : void();
	
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

		this->multiplier = 2;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);		
		if (status = this->decompress(fsrc, fdst))
			goto cleanup;
	}
	else if (this->context.compression == NO_COMPRESS && this->context.crypto_check) { // Only crypto
	#ifdef CRYPTOGRAPH_EGE
		fdst = fopen(pathDest, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 2;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);		
		if (status = this->decrypt(fsrc, fdst))
			goto cleanup;
	#else
		return CRYPT_NOT_SUPPORTED;
	#endif // CRYPTOGRAPH_EGE
	}
	else if (this->context.compression != NO_COMPRESS && this->context.crypto_check) { // Both compress + crypto
	#ifdef CRYPTOGRAPH_EGE
		while (std::experimental::filesystem::exists(tempname)) // For ensure thread safety
			tmpnam(tempname);
		fdst = fopen(tempname, "wb");
		if (!(fsrc && fdst)) {
			status = FILE_INPUT_OUTPUT_ERR;
			goto cleanup;
		}

		this->multiplier = 1;
		fseek(fsrc, sizeof(ege::fileProperties) + 8 + sizeof(size_t), SEEK_CUR);
		if (status = this->decrypt(fsrc, fdst))
			goto cleanup;
		this->progress = 50;

		fclose(fsrc); fsrc = fopen(tempname, "rb");
		fclose(fdst); fdst = fopen(pathDest, "wb");

		if (status = this->decompress(fsrc, fdst))
			goto cleanup;
	#else
		return CRYPT_NOT_SUPPORTED;
	#endif // CRYPTOGRAPH_EGE
	}

cleanup:
	this->progress = 100;
	fclose(fsrc); fclose(fdst);

	if (status)
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();

	std::experimental::filesystem::exists(tempname) ? std::experimental::filesystem::remove(tempname) : void();

	return status;
}

char* ege::Filer::getPath()
{
	char *path = (char*)malloc(FILENAME_MAX);
	strcpy(path, this->path);
	return path;
}

void ege::Filer::setCompressionType(ege::COMPRESSION_METHOD id)
{
	this->compression_type = id;
}

ege::COMPRESSION_METHOD ege::Filer::getCompressionType(char * type)
{
	if (type)
		strcpy(type, this->strcomptype(this->compression_type));
	return this->compression_type;
}

#ifdef CRYPTOGRAPH_EGE
void ege::Filer::setKey(Ipp8u * key, size_t keylen)
{
	this->key = (Ipp8u*)malloc(sizeof(Ipp8u)*keylen);
	memcpy(this->key, key, sizeof(Ipp8u)*keylen);
	this->keylen = keylen;
}

Ipp8u * ege::Filer::getKey(size_t *keylen)
{
	Ipp8u* buff = (Ipp8u*)malloc(sizeof(Ipp8u)*this->keylen);
	memcpy(buff, this->key, sizeof(Ipp8u)*this->keylen);
	if (keylen != nullptr)
		*keylen = this->keylen;
	return buff;
}

void ege::Filer::setEncryptionMethod(ege::CRYPTO_METHOD id)
{
	this->crypto_type = id;
}

ege::CRYPTO_METHOD ege::Filer::getEncryptionMethod(char * type)
{
	if (type)
		strcpy(type, this->strcrypttype(this->crypto_type));
	return this->crypto_type;
}

void ege::Filer::setHashMethod(IppHashAlgId id)
{
	this->hash_type = id;
}

IppHashAlgId ege::Filer::getHashMethod(char * type)
{
	if (type)
		strcpy(type, this->strhashtype(this->hash_type));
	return this->hash_type;
}
#endif

ege::Filer::~Filer()
{
	free(this->path);
#ifdef CRYPTOGRAPH_EGE
	free(this->key);
#endif
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
		std::experimental::filesystem::exists(pathDest) ? std::experimental::filesystem::remove(pathDest) : void();
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
