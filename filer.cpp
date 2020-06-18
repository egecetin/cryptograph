#include "filer.h"

bool ege::filer::checkfile(char * file)
{
	return std::experimental::filesystem::exists(file);
}

char * ege::filer::readLastWrite(char* file)
{
	auto lasttime = std::experimental::filesystem::last_write_time(file);
	std::time_t cftime = decltype(lasttime)::clock::to_time_t(lasttime);
	return std::asctime(std::localtime(&cftime));
}

int64_t ege::filer::readSize(char* file)
{
	return std::experimental::filesystem::file_size(file);
}

const char * ege::filer::strcomptype(ege::COMPRESSION_METHOD id)
{
	switch (id)
	{
	case ege::COMPRESSION_METHOD::NO_COMPRESS:
		return "No compression";
	default:
		return "Unknown compression code.";
	}
}

ERR_STATUS ege::filer::copy(char * pathSrc, char * pathDest)
{
	FILE *src = fopen(this->path, "rb");
	FILE *dest = fopen(pathDest, "wb");

	char buf[BUFSIZ];
	size_t size;

	while (size = fread(buf, BUFSIZ*sizeof(char), 1, src)) {
		fwrite(buf, size*sizeof(char), 1, dest);
	}

	fclose(src);
	fclose(dest);

	return NO_ERROR;
}

void ege::filer::prepareHeader(char* pathSrc)
{
	std::experimental::filesystem::path path = pathSrc;

	this->context.size = this->readSize(pathSrc);
	strcpy(this->context.filename, path.stem().string().c_str());
	strcpy(this->context.extension, path.extension().string().c_str());
	strcpy(this->context.lastwrite, this->readLastWrite(pathSrc));
	this->context.compression = this->getCompressionType;
#ifdef CRYPTOGRAPH_EGE
	this->context.crypto = this->getEncryptionMethod();
	this->context.hashmethod = this->getHashMethod();
#endif // CRYPTOGRAPH_EGE

}

ERR_STATUS ege::filer::readHeader(char * pathSrc) // <------------------------------------------
{
	FILE *fptr = fopen(pathSrc, "rb");
	fread(&this->context, sizeof(this->context), 1, fptr);

	if (strcmp(this->context.codeword, "EGE!"))
		return FILE_NOT_SUPPORTED;
#ifdef CRYPTOGRAPH_EGE
	if (!strcmp(this->context.extword, "END!")) {
		strcpy(this->context.extword, "EXT!");
		this->context.crypto = ege::CRYPTO_METHOD::NO_ENCRYPT;
		this->context.hashmethod = ippHashAlg_Unknown;
		strcpy(this->context.endword, "END!");
		return NO_ERROR;
	}
#else
	if (!strcmp(this->context.endword, "EXT!"))
		return CRYPT_NOT_SUPPORTED;
	if (!strcmp(this->context.endword, "END!"))
		return NO_ERROR;
#endif // CRYPTOGRAPH_EGE

	return FILE_NOT_SUPPORTED;
}

void ege::filer::writeHeader(char * pathDest) // <------------------------------------------
{
	FILE *fptr = fopen(pathDest,"wb");
	fwrite(&this->context, sizeof(this->context), 1, fptr);
	fclose(fptr);
}

#ifdef CRYPTOGRAPH_EGE
const char * ege::filer::strhashtype(IppHashAlgId id)
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

const char * ege::filer::strcrypttype(ege::CRYPTO_METHOD id)
{
	// Always return 5 character ('CODE' + '\0')
	switch (id)
	{
	case ege::CRYPTO_METHOD::NO_ENCRYPT:
		return "0000";
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
#endif

ege::filer::filer(char * pathSrc)
{
	this->path = (char*)malloc(sizeof(char)*FILENAME_MAX);
	pathSrc ? this->setPath(pathSrc) : void();
}

ERR_STATUS ege::filer::setPath(char * pathSrc)
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

ERR_STATUS ege::filer::moveFile(char * pathDest, bool overwrite)
{
	if (this->path)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;
	this->path[0] == pathDest[0] ? rename(this->path, pathDest) : this->copy(this->path, pathDest);
}

ERR_STATUS ege::filer::copyFile(char * pathDest, bool overwrite)
{
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	return this->copy(this->path, pathDest);
}

ERR_STATUS ege::filer::pack(char * pathDest, bool overwrite)
{
	ERR_STATUS status = NO_ERROR;
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	char *tempname = tmpnam(nullptr);
	this->writeHeader(tempname);

	if (status = this->compress(this->path, tempname)) {
		free(tempname);
		return status;
	}

#ifdef CRYPTOGRAPH_EGE
	if (status = this->encrypt(tempname, pathDest)) {
		free(tempname);
		return status;
	}
#else
	pathDest[0] == tempname[0] ? rename(tempname, pathDest) : status = this->copy(tempname, pathDest);
#endif // CRYPTOGRAPH_EGE

	free(tempname);
	return status;	
}

ERR_STATUS ege::filer::unpack(char * pathDest, bool overwrite)
{
	ERR_STATUS status = NO_ERROR;
	if (this->path == nullptr)
		return FILE_NOT_SET;
	if (!overwrite && this->checkfile(pathDest))
		return FILE_ALREADY_EXIST;

	char *tempname = tmpnam(nullptr);
	this->readHeader(tempname);

	if (status = this->decompress(this->path, tempname)) {
		free(tempname);
		return status;
	}

#ifdef CRYPTOGRAPH_EGE
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

char* ege::filer::getPath()
{
	char path[FILENAME_MAX];
	strcpy(path, this->path);
	return path;
}

void ege::filer::setCompressionType(ege::COMPRESSION_METHOD id)
{
	this->compression_type = id;
}

ege::COMPRESSION_METHOD ege::filer::getCompressionType(char * type)
{
	if (type)
		strcpy(type, this->strcomptype(this->compression_type));
	return this->compression_type;
}

#ifdef CRYPTOGRAPH_EGE
void ege::filer::setKey(Ipp8u * key, size_t keylen)
{
	this->key = (Ipp8u*)malloc(sizeof(Ipp8u)*keylen);
	memcpy(this->key, key, sizeof(Ipp8u)*keylen);
}

Ipp8u * ege::filer::getKey(size_t & keylen)
{
	Ipp8u* buff = (Ipp8u*)malloc(sizeof(Ipp8u)*this->keylen);
	memcpy(buff, this->key, sizeof(Ipp8u)*this->keylen);
	return buff;
}

void ege::filer::setEncryptionMethod(ege::CRYPTO_METHOD id)
{
	this->crypto_type = id;
}

ege::CRYPTO_METHOD ege::filer::getEncryptionMethod(char * type)
{
	if (type)
		strcpy(type, this->strcrypttype(this->crypto_type));
	return this->crypto_type;
}

void ege::filer::setHashMethod(IppHashAlgId id)
{
	this->hash_type = id;
}

IppHashAlgId ege::filer::getHashMethod(char * type)
{
	if (type)
		strcpy(type, this->strhashtype(this->hash_type));
	return this->hash_type;
}
#endif

ege::filer::~filer()
{
	free(this->path);
#ifdef CRYPTOGRAPH_EGE
	free(this->key);
#endif
}
