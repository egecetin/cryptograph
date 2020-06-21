#include "filer.h"

bool ege::Filer::checkfile(char * file)
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

ERR_STATUS ege::Filer::copy(char * pathSrc, char * pathDest, int prepend)
{
	size_t size;
	char buf[BUFSIZ];	

	FILE *src = fopen(this->path, "rb");
	FILE *dest = fopen(pathDest, "wb");
	if (!(src && dest))
		return FILE_INPUT_OUTPUT_ERR;
	if (prepend == 1) // Allocate header
		fwrite('\0', 1, sizeof(ege::fileProperties) + 8, dest);
	if (prepend == -1) { // Deallocate header
		fread(buf, 1, 4, src);
		fread(&size, sizeof(size_t), 1, src); // Read size
		fseek(src, size + 4, SEEK_CUR);
	}

	while (size = fread(buf, 1, BUFSIZ, src)) {
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
	strcpy(this->context.filename, path.stem().string().c_str());
	strcpy(this->context.extension, path.extension().string().c_str());
	strcpy(this->context.lastwrite, this->readLastWrite(this->path));
	this->context.compression = this->getCompressionType;
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

	char buffer[5];
	size_t size = 0;

	fread(buffer, 5, 1, fptr);
	if (strcmp(buffer, "EGE!"))
		return FILE_NOT_SUPPORTED;
	fread(&size, sizeof(size_t), 1, fptr); // Read size

	if (size == sizeof(ege::fileProperties)) { // HOST + CLIENT EQUAL
		fread(&this->context, sizeof(ege::fileProperties), 1, fptr);
		
		fread(buffer, 5, 1, fptr);
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
		return "No Hash Check.";
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
ERR_STATUS ege::Filer::encrypt(char * pathSrc, char * pathDest)
{
	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");

	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::experimental::filesystem::exists(dest) ? std::experimental::filesystem::remove(dest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	size_t size;
	ERR_STATUS status = NO_ERROR;	
	ege::Hash_Coder hasher(this->hash_type);
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFSIZ);
	Ipp8u *cipher = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFSIZ);

	switch (this->crypto_type)
	{
	case ege::CRYPTO_METHOD::AES:
	{
		AES_Crypt cryptograph(this->key);
		while (size = fread(buff, 1, BUFSIZ, src)) {
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			if (status = hasher.update(cipher, size))
				break;
			fwrite(cipher, size, 1, dest);
		}
	}
	case ege::CRYPTO_METHOD::SMS4:
	{
		SMS4_Crypt cryptograph(this->key);
		while (size = fread(buff, 1, BUFSIZ, src)) {
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			if (status = hasher.update(cipher, size))
				break;
			fwrite(cipher, size, 1, dest);
		}
	}
	case ege::CRYPTO_METHOD::RSA:
		// Allocated
	case ege::CRYPTO_METHOD::ECCP:
		// Allocated
	default:
		status = CRYPT_UNKNOWN_METHOD;
	}

	if (!status)
		status = hasher.getHash(this->context.hashcode);
		
	for (size_t i = 0; i < BUFSIZ; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	fclose(src);
	fclose(dest);
	return status;
}
ERR_STATUS ege::Filer::decrypt(char * pathSrc, char * pathDest)
{
	FILE *src = fopen(pathSrc, "rb");
	FILE *dest = fopen(pathDest, "wb");
	
	if (!(src && dest)) {
		fclose(src);
		fclose(dest);
		std::experimental::filesystem::exists(dest) ? std::experimental::filesystem::remove(dest) : void();
		return FILE_INPUT_OUTPUT_ERR;
	}

	int size;
	ERR_STATUS status = NO_ERROR;
	ege::Hash_Coder hasher(this->hash_type);
	Ipp8u *buff = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFSIZ);
	Ipp8u *cipher = (Ipp8u*)malloc(sizeof(Ipp8u)*BUFSIZ);

	switch (this->crypto_type)
	{
	case ege::CRYPTO_METHOD::AES:
	{
		AES_Crypt cryptograph(this->key);
		while (size = fread(cipher, 1, BUFSIZ, src)) {
			if (status = hasher.update(cipher, size))
				break;
			if (status = cryptograph.decryptMessage(cipher, buff, size))
				break;
			fwrite(buff, size, 1, dest);
		}
	}
	case ege::CRYPTO_METHOD::SMS4:
	{
		SMS4_Crypt cryptograph(this->key);
		while (size = fread(cipher, 1, BUFSIZ, src)) {
			if (status = hasher.update(cipher, size))
				break;
			if (status = cryptograph.decryptMessage(cipher, buff, size))
				break;
			fwrite(buff, size, 1, dest);
		}
	}
	case ege::CRYPTO_METHOD::RSA:
		// Allocated
	case ege::CRYPTO_METHOD::ECCP:
		// Allocated
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
	for (size_t i = 0; i < BUFSIZ; ++i)
		buff[i] = 0;
	free(buff);
	free(cipher);

	fclose(src);
	fclose(dest);
	return status;
}
#endif

ege::Filer::Filer(char * pathSrc)
{
	this->path = (char*)malloc(sizeof(char)*FILENAME_MAX);
	pathSrc ? this->setPath(pathSrc) : void();
}

ERR_STATUS ege::Filer::setPath(char * pathSrc)
{
	if (strlen(pathSrc) < FILENAME_MAX && pathSrc) {
		if (this->checkfile(this->path)) {
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
	this->path[0] == pathDest[0] ? rename(this->path, pathDest) : this->copy(this->path, pathDest, 0);
}

ERR_STATUS ege::Filer::copyFile(char * pathDest, bool overwrite)
{
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	return this->copy(this->path, pathDest, 0);
}

ERR_STATUS ege::Filer::pack(char * pathDest, bool overwrite)
{
	ERR_STATUS status = NO_ERROR;
	char tempname[FILENAME_MAX]; tmpnam(tempname);
	char tempname2[FILENAME_MAX]; tmpnam(tempname2);

	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	this->prepareHeader();

	char *src = this->path;
	char *dest = tempname;	

	if (this->context.compression != NO_COMPRESS) {
		while (std::experimental::filesystem::exists(dest)) // For ensure thread safety
			tmpnam(dest);
		if (status = this->compress(src, dest)) {
			return status;
		}
		if (this->context.crypto_check == 1) {
			src = dest;
			dest = tempname2;
		}
	}

#ifdef CRYPTOGRAPH_EGE
	if (this->context.crypto != NO_ENCRYPT) {

		if (this->key == nullptr)
			return CRYPT_KEY_NOT_SET;
		while (std::experimental::filesystem::exists(dest)) // For ensure thread safety
			tmpnam(dest);
		if (status = this->encrypt(src, dest)) {
			return status;
		}
	}
#endif // CRYPTOGRAPH_EGE

	status = this->copy(dest, pathDest, 1);
	this->writeHeader(pathDest);

	std::experimental::filesystem::exists(tempname) ? std::experimental::filesystem::remove(tempname) : void();
	std::experimental::filesystem::exists(tempname2) ? std::experimental::filesystem::remove(tempname2) : void();
	return status;	
}

ERR_STATUS ege::Filer::unpack(char * pathDest, bool overwrite)
{
	ERR_STATUS status = NO_ERROR;
	char tempname[FILENAME_MAX]; tmpnam(tempname);
	char tempname2[FILENAME_MAX]; tmpnam(tempname2);

	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	if (status = this->readHeader(this->path) != NO_ERROR)
		return status;
	this->configFromHeader();

	this->copy(this->path, tempname, -1);
	char *src = tempname;
	char *dest = tempname2;

#ifdef CRYPTOGRAPH_EGE
	if (this->context.crypto != NO_ENCRYPT) {
		if (this->key == nullptr)
			return CRYPT_KEY_NOT_SET;
		while (std::experimental::filesystem::exists(dest)) // For ensure thread safety
			tmpnam(dest);
		if (status = this->decrypt(src, dest)) {
			return status;
		}
		if (this->context.compression != NO_COMPRESS) {
			src = tempname2;
			dest = tempname;
		}
	}
#endif // CRYPTOGRAPH_EGE

	if (this->context.compression != NO_COMPRESS) {
		while (std::experimental::filesystem::exists(dest)) // For ensure thread safety
			tmpnam(dest);
		if (status = this->decompress(src, dest)) {
			return status;
		}
	}
	status = this->copy(dest, pathDest, 0);

	std::experimental::filesystem::exists(tempname) ? std::experimental::filesystem::remove(tempname) : void();
	std::experimental::filesystem::exists(tempname2) ? std::experimental::filesystem::remove(tempname2) : void();
	return status;
}

char* ege::Filer::getPath()
{
	char path[FILENAME_MAX];
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
}

Ipp8u * ege::Filer::getKey(size_t & keylen)
{
	Ipp8u* buff = (Ipp8u*)malloc(sizeof(Ipp8u)*this->keylen);
	memcpy(buff, this->key, sizeof(Ipp8u)*this->keylen);
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
