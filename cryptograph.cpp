#include "cryptograph.h"

ege::AES_Crypt::AES_Crypt(Ipp8u *pkey, size_t keyLen)
{
	ERR_STATUS status = NO_ERROR;
	int ctxSize = 0;

	// Init context
	status = ippsAESGetSize(&ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	this->key = (IppsAESSpec*)(new Ipp8u[ctxSize]);
	this->ctr = new Ipp8u[AES_CTR_SIZE];
	memset(this->ctr, 1, AES_CTR_SIZE);

	if (pkey == nullptr)
		pkey = rand8(keyLen / 8);
	
	status = ippsAESInit(pkey, keyLen / 8, this->key, ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));

	// Since no throw set key length
	this->keyLen = keyLen;
}

ERR_STATUS ege::AES_Crypt::setKey(const Ipp8u *pkey, size_t keyLen)
{
	ERR_STATUS status;
	status = ippsAESSetKey(pkey, keyLen / 8, this->key);

	if (status == NO_ERROR)
		this->keyLen = keyLen;
	
	return status;
}

ERR_STATUS ege::AES_Crypt::resetCtr(Ipp8u * ctr, int ctrBitLen)
{
	if (ctrBitLen > AES_CTR_SIZE)
		return CRYPT_CTR_OVERFLOW;
	if (this->ctr)
		delete this->ctr;
	
	this->ctr = new Ipp8u[AES_CTR_SIZE];
	if (!ctr)
		memset(this->ctr, 1, AES_CTR_SIZE);
	else
		memcpy(this->ctr + AES_CTR_SIZE - (ctrBitLen / 8), ctr, ctrBitLen / 8);

	return NO_ERROR;
}

ERR_STATUS ege::AES_Crypt::encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr) // If ctr not passed use internal ctr
		return ippsAESEncryptCTR(msg, ciphertext, lenmsg, this->key, this->ctr, AES_CTR_SIZE * 8);
	else
		return ippsAESEncryptCTR(msg, ciphertext, lenmsg, this->key, ctr, ctrBitLen);
}

ERR_STATUS ege::AES_Crypt::decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr) // If ctr not passed use internal ctr
		return ippsAESDecryptCTR(ciphertext, msg, lenmsg, this->key, this->ctr, AES_CTR_SIZE * 8);
	else
		return ippsAESDecryptCTR(ciphertext, msg, lenmsg, this->key, ctr, ctrBitLen);
}

ege::AES_Crypt::~AES_Crypt()
{
	// If key is set overwrite sensitive data
	if (this->key != nullptr) {
		int ctxSize;
		ippsAESGetSize(&ctxSize);
		ippsAESInit(nullptr, this->keyLen / 8, key, ctxSize);
		delete[](Ipp8u*)this->key;
		this->key = nullptr;
		this->keyLen = 0;
	}

	delete[] this->ctr;
}

inline Ipp8u* ege::AES_Crypt::rand8(int size)
{
	Ipp8u* pX = new Ipp8u[size];
	std::srand(std::time(nullptr)); // Seed with current time
	for (int n = 0; n < size; ++n)
		pX[n] = rand();
	return pX;
}

ege::SMS4_Crypt::SMS4_Crypt(Ipp8u *pkey, size_t keyLen)
{
	ERR_STATUS status = NO_ERROR;
	int ctxSize = 0;

	status = ippsSMS4GetSize(&ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	this->key = (IppsSMS4Spec*)(new Ipp8u[ctxSize]);
	this->ctr = new Ipp8u[SMS4_CTR_SIZE];
	memset(this->ctr, 1, SMS4_CTR_SIZE);

	if (pkey == nullptr) {
		pkey = rand8(keyLen / 8);
	}

	status = ippsSMS4Init(pkey, keyLen / 8, key, ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));

	this->keyLen = keyLen;
}

ERR_STATUS ege::SMS4_Crypt::setKey(const Ipp8u *key, size_t keyLen)
{
	return ippsSMS4SetKey(key, keyLen / 8, this->key);
}

ERR_STATUS ege::SMS4_Crypt::resetCtr(Ipp8u * ctr, int ctrBitLen)
{
	if (ctrBitLen > SMS4_CTR_SIZE)
		return CRYPT_CTR_OVERFLOW;
	if (this->ctr)
		delete this->ctr;

	this->ctr = new Ipp8u[SMS4_CTR_SIZE];
	if (!ctr)
		memset(this->ctr, 1, SMS4_CTR_SIZE);
	else
		memcpy(this->ctr + SMS4_CTR_SIZE - (ctrBitLen / 8), ctr, ctrBitLen / 8);

	return NO_ERROR;
}

ERR_STATUS ege::SMS4_Crypt::encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsSMS4EncryptCTR(msg, ciphertext, lenmsg, this->key, this->ctr, SMS4_CTR_SIZE * 8);
	else
		return ippsSMS4EncryptCTR(msg, ciphertext, lenmsg, this->key, ctr, ctrBitLen);
}

ERR_STATUS ege::SMS4_Crypt::decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsSMS4DecryptCTR(ciphertext, msg, lenmsg, this->key, this->ctr, SMS4_CTR_SIZE * 8);
	else
		return ippsSMS4DecryptCTR(ciphertext, msg, lenmsg, this->key, ctr, ctrBitLen);
}

ege::SMS4_Crypt::~SMS4_Crypt()
{
	if (this->key != nullptr) {
		int ctxSize;
		ippsSMS4GetSize(&ctxSize);
		ippsSMS4Init(nullptr, this->keyLen / 8, key, ctxSize);
		delete[](Ipp8u*)this->key;
		this->key = nullptr;
		this->keyLen = 0;
	}

	delete[] this->ctr;
}

inline Ipp8u * ege::SMS4_Crypt::rand8(int size)
{
	Ipp8u* pX = new Ipp8u[size];
	std::srand(std::time(nullptr)); // Seed with current time
	for (int n = 0; n < size; ++n)
		pX[n] = rand();
	return pX;
}

ege::Hash_Coder::Hash_Coder(IppHashAlgId id)
{
	ERR_STATUS status;
	int ctxSize;

	status = ippsHashGetSize(&ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));

	this->context = (IppsHashState*)new Ipp8u[ctxSize];
	status = ippsHashInit(this->context, id);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
}

ERR_STATUS ege::Hash_Coder::update(Ipp8u * msg, size_t lenmsg)
{
	return ippsHashUpdate(msg, lenmsg, this->context);
}

ERR_STATUS ege::Hash_Coder::calcFileHash(FILE * fptr, Ipp8u *hashCode)
{
	ERR_STATUS status = NO_ERROR;
	size_t size = 0;
	Ipp8u buf[MAX_HASH_MSG_LEN];
	while ((size = fread(buf, 1, MAX_HASH_MSG_LEN, fptr))) {
		status = this->update(buf, size);
		if (status)
			return status;
	}

	return this->getHash(hashCode);
}

ERR_STATUS ege::Hash_Coder::getHash(Ipp8u *code)
{
	return ippsHashFinal(code, this->context);
}

ege::Hash_Coder::~Hash_Coder()
{
	delete[](Ipp8u*)this->context;
	this->context = nullptr;
}
