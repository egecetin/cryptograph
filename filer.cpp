#include "filer.h"

char * ege::filer::readLastWrite(const std::experimental::filesystem::path fptr)
{
	auto lasttime = std::experimental::filesystem::last_write_time(fptr);
	std::time_t cftime = decltype(lasttime)::clock::to_time_t(lasttime);
	return std::asctime(std::localtime(&cftime));
}

void ege::filer::setPath(const char * pathSrc)
{
	memcpy(this->path, pathSrc, strlen(pathSrc));
}

void ege::filer::moveFile(const char * pathDest)
{
	this->path[0] == pathDest[0] ? rename(this->path, pathDest) : this->copyFile(pathDest);
}

void ege::filer::copyFile(const char * pathDest)
{
	FILE *src = fopen(this->path, "rb");
	FILE *dest = fopen(pathDest, "wb");

	char buf[BUFSIZ];
	size_t size;

	while (size = fread(buf, 1, BUFSIZ, src)) {
		fwrite(buf, 1, size, dest);
	}

	fclose(src);
	fclose(dest);
}

char* ege::filer::getPath()
{
	char path[FILENAME_MAX];
	memcpy(path, this->path, FILENAME_MAX);
	return path;
}

void ege::filer::setCompressionType(COMPRESSION_METHOD id)
{
	this->compression_type = id;
}

ege::COMPRESSION_METHOD ege::filer::getCompressionType(char * type)
{
	if (type)
		memcpy(type, strcomptype(this->compression_type), 5);
	return this->compression_type;
}

void ege::filer::setEncryptionMethod(CRYPTO_METHOD id)
{
	this->crypto_type = id;
}

ege::CRYPTO_METHOD ege::filer::getEncryptionMethod(char * type)
{
	if (type)
		memcpy(type, strcrypttype(this->crypto_type), 5);
	return this->crypto_type;
}
