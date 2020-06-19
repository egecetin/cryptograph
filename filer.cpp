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

ERR_STATUS ege::Filer::copy(char * pathSrc, char * pathDest)
{
	FILE *src = fopen(this->path, "rb");
	FILE *dest = fopen(pathDest, "wb");
	if (!(src && dest))
		return FILE_INPUT_OUTPUT_ERR;

	char buf[BUFSIZ];
	size_t size;

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
	FILE *fptr = fopen(pathDest,"wb");
	if (!fptr)
		return FILE_INPUT_OUTPUT_ERR;

	size_t size = sizeof(ege::fileProperties);

	fwrite("EGE!", sizeof(char) * 5, 1, fptr);	
	fwrite(&size, sizeof(size_t), 1, fptr);
	fwrite(&this->context, sizeof(this->context), 1, fptr);
	fwrite("END!", sizeof(char) * 5, 1, fptr);
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
	if (!(src && dest))
		return FILE_INPUT_OUTPUT_ERR;

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
			if (status = hasher.update(buff, size))
				break;
			if (status = cryptograph.encryptMessage(buff, size, cipher))
				break;
			fwrite(cipher, size, 1, dest);
		}
	}
	case ege::CRYPTO_METHOD::SMS4:

	case ege::CRYPTO_METHOD::RSA:

	case ege::CRYPTO_METHOD::ECCP:

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
	this->path[0] == pathDest[0] ? rename(this->path, pathDest) : this->copy(this->path, pathDest);
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
	ERR_STATUS status = NO_ERROR;
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	this->prepareHeader();

	char *tempname = tmpnam(nullptr);
	if (status = this->compress(this->path, tempname)) {
		free(tempname);
		return status;
	}

#ifdef CRYPTOGRAPH_EGE
	// Check key is null?
	if (status = this->encrypt(tempname, pathDest)) {
		free(tempname);
		return status;
	}
#else
	pathDest[0] == tempname[0] ? rename(tempname, pathDest) : status = this->copy(tempname, pathDest);
#endif // CRYPTOGRAPH_EGE
	
	this->writeHeader(pathDest);

	free(tempname);
	return status;	
}

ERR_STATUS ege::Filer::unpack(char * pathDest, bool overwrite)
{
	ERR_STATUS status = NO_ERROR;
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	if (status = this->readHeader(this->path) != NO_ERROR)
		return status;
	this->configFromHeader();

	char *tempname = tmpnam(nullptr);
	if (status = this->decompress(this->path, tempname)) {
		free(tempname);
		return status;
	}

#ifdef CRYPTOGRAPH_EGE
	// Check key is null?
	if (status = this->decrypt(tempname, pathDest)) {
		free(tempname);
		return status;
	}
#else
	pathDest[0] == tempname[0] ? rename(tempname, pathDest) : status = this->copy(tempname, pathDest);
#endif // CRYPTOGRAPH_EGE

	free(tempname);
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
