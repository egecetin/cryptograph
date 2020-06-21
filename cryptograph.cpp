#include "cryptograph.h"

ege::RSA_Crypt::RSA_Crypt(const int bitsize, Ipp8u *private_key, size_t privateSize, Ipp8u *public_key, size_t publicSize)
{
	ERR_STATUS status = NO_ERROR;

	// Init variables
	int ctxSize;

	this->bitsize = bitsize;
	this->bitsP = (this->bitsize + 1) / 2;
	this->bitsQ = this->bitsize - this->bitsP;
	this->generate_RandomGenerator(160, this->pRNG);		// Init random generator
	this->generate_PrimeGenerator(this->bitsize, this->pPG);// Init prime number generator
	this->seed = rand32(256 / 32);

	if (private_key == nullptr && public_key == nullptr) {

		BigNumber sourcePExp(rand32(1), 1, IppsBigNumPOS);										// Source of public exponential
		BigNumber modulus(rand32(this->bitsize / 32), this->bitsize / 32, IppsBigNumPOS);		// Modulus
		BigNumber publicExp(rand32(this->bitsize / 32), this->bitsize / 32, IppsBigNumPOS);		// Public exponential
		BigNumber privateExp(rand32(this->bitsize / 32), this->bitsize / 32, IppsBigNumPOS);	// Public exponential

		// Init Private key
		status = ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->privateKey = (IppsRSAPrivateKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, this->privateKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Init buffer
		status = ippsRSA_GetBufferSizePrivateKey(&ctxSize, this->privateKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->buffer = new Ipp8u[ctxSize];

		// Generate keys for RSA
		size_t ctr = 0;
		do {
			status = ippsRSA_GenerateKeys(sourcePExp, modulus, publicExp, privateExp, this->privateKey, buffer, N_TRIAL, this->pPG, ippsPRNGen, this->pRNG);
			++ctr;
		} while (status == ippStsInsufficientEntropy && ctr < MAX_TRIAL);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Init Public key		
		status = ippsRSA_GetSizePublicKey(modulus.BitSize(), publicExp.BitSize(), &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		this->publicKey = (IppsRSAPublicKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPublicKey(modulus.BitSize(), publicExp.BitSize(), this->publicKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		status = ippsRSA_SetPublicKey(modulus, publicExp, this->publicKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Validate keys
		status = ippsRSA_ValidateKeys(&ctxSize, this->publicKey, this->privateKey, NULL, buffer, N_TRIAL, this->pPG, ippsPRNGen, this->pRNG);
		if (ctxSize == IS_INVALID_KEY)
			throw runtime_error(ege::sterror(ippStsContextMatchErr, IPP_ID));

#ifdef _DEBUG
		std::cout << "-----------------------------------------------------------------------------------------" << std::endl;
		std::cout << "Modulus (" << modulus.BitSize() << ")" << std::endl;
		std::cout << modulus << std::endl << std::endl;

		std::cout << "Public exponential (" << publicExp.BitSize() << ")" << std::endl;
		std::cout << publicExp << std::endl << std::endl;

		std::cout << "Private exponential (" << privateExp.BitSize() << ")" << std::endl;
		std::cout << privateExp << std::endl << std::endl;
#endif // _DEBUG

		// Overwrite
		sourcePExp = BigNumber::Zero();
		modulus = BigNumber::Zero();
		publicExp = BigNumber::Zero();
		privateExp = BigNumber::Zero();

	}
	else if (private_key == nullptr && public_key != nullptr) {

		// Split modulus and publicExp
		BigNumber modulus((Ipp32u*)&public_key[0], this->bitsize / 32, IppsBigNumPOS);
		BigNumber publicExp((Ipp32u*)&public_key[this->bitsize / 32], publicSize - this->bitsize / 32, IppsBigNumPOS);

		// Init Public key		
		status = ippsRSA_GetSizePublicKey(modulus.BitSize(), publicExp.BitSize(), &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		this->publicKey = (IppsRSAPublicKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPublicKey(modulus.BitSize(), publicExp.BitSize(), this->publicKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		status = ippsRSA_SetPublicKey(modulus, publicExp, this->publicKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Init buffer
		status = ippsRSA_GetBufferSizePublicKey(&ctxSize, this->publicKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->buffer = new Ipp8u[ctxSize];

		// Overwrite
		modulus = BigNumber::Zero();
		publicExp = BigNumber::Zero();
	}
	else if (public_key == nullptr && private_key != nullptr) {

		// Split p and q
		BigNumber p((Ipp32u*)&private_key[0], this->bitsP / 32, IppsBigNumPOS);
		BigNumber q((Ipp32u*)&private_key[this->bitsP / 32], this->bitsQ / 32, IppsBigNumPOS);
		BigNumber dP, dQ, invQ;

		// Init Private key
		status = ippsRSA_GetSizePrivateKeyType2(this->bitsP, this->bitsQ, &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->privateKey = (IppsRSAPrivateKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPrivateKeyType2(this->bitsP, this->bitsQ, this->privateKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		status = ippsRSA_SetPrivateKeyType2(p, q, dP, dQ, invQ, this->privateKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Init buffer
		status = ippsRSA_GetBufferSizePrivateKey(&ctxSize, this->privateKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->buffer = new Ipp8u[ctxSize];

		// Overwrite
		p = BigNumber::Zero();
		q = BigNumber::Zero();
		dP = BigNumber::Zero();
		dQ = BigNumber::Zero();
		invQ = BigNumber::Zero();
	}
	else {
		// Split modulus and publicExp
		BigNumber modulus((Ipp32u*)&public_key[0], this->bitsize / 32, IppsBigNumPOS);
		BigNumber publicExp((Ipp32u*)&public_key[this->bitsize / 32], publicSize - this->bitsize / 32, IppsBigNumPOS);

		// Init Public key		
		status = ippsRSA_GetSizePublicKey(modulus.BitSize(), publicExp.BitSize(), &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		this->publicKey = (IppsRSAPublicKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPublicKey(modulus.BitSize(), publicExp.BitSize(), this->publicKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		status = ippsRSA_SetPublicKey(modulus, publicExp, this->publicKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Split p and q
		BigNumber p((Ipp32u*)&private_key[0], this->bitsP / 32, IppsBigNumPOS);
		BigNumber q((Ipp32u*)&private_key[this->bitsP / 32], this->bitsQ / 32, IppsBigNumPOS);
		BigNumber dP, dQ, invQ;

		// Init Private key
		status = ippsRSA_GetSizePrivateKeyType2(this->bitsP, this->bitsQ, &ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->privateKey = (IppsRSAPrivateKeyState*)(new Ipp8u[ctxSize]);

		status = ippsRSA_InitPrivateKeyType2(this->bitsP, this->bitsQ, this->privateKey, ctxSize);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		status = ippsRSA_SetPrivateKeyType2(p, q, dP, dQ, invQ, this->privateKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));

		// Init buffer
		status = ippsRSA_GetBufferSizePrivateKey(&ctxSize, this->privateKey);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
		this->buffer = new Ipp8u[ctxSize];

		// Overwrite
		p = BigNumber::Zero();
		q = BigNumber::Zero();
		dP = BigNumber::Zero();
		dQ = BigNumber::Zero();
		invQ = BigNumber::Zero();
	}
}

ERR_STATUS ege::RSA_Crypt::setKey(int key_type, Ipp8u * key, int keySize)
{
	ERR_STATUS status = NO_ERROR;
	std::string buffer;
	size_t size;

	if (!key)
		return ippStsNullPtrErr;

	switch (key_type)
	{
	case IppRSApublic:
	{
		BigNumber modulus, publicExp;

		modulus.Set((Ipp32u*)key, this->bitsize / 32, IppsBigNumPOS);
		publicExp.Set((Ipp32u*)&key[this->bitsize / 32], keySize - this->bitsize / 32, IppsBigNumPOS);

		if (status = ippsRSA_SetPublicKey(modulus, publicExp, this->publicKey))
			return status;
	}
	case IppRSAprivate:
	{
		BigNumber p, q, dP, dQ, invQ;

		p.Set((Ipp32u*)key, (keySize + 1) / 2, IppsBigNumPOS);
		q.Set((Ipp32u*)&key[(keySize + 1) / 2], (keySize - 1) / 2, IppsBigNumPOS);

		if (status = ippsRSA_SetPrivateKeyType2(p, q, dP, dQ, invQ, this->privateKey))
			return status;
	}
	default:
		return CRYPT_UNKNOWN_KEY_TYPE;
	}

	return NO_ERROR;
}

void ege::RSA_Crypt::printKeys()
{
	std::cout << "-----------------------------------------------------------------------------------------" << std::endl;

	if (this->publicKey != nullptr) {
		BigNumber modulus, publicExp;

		ippsRSA_GetPublicKey(modulus, publicExp, this->publicKey);

		std::cout << "Modulus (" << modulus.BitSize() << ")" << std::endl;
		std::cout << modulus << std::endl << std::endl;

		std::cout << "Public exponential (" << publicExp.BitSize() << ")" << std::endl;
		std::cout << publicExp << std::endl << std::endl;

		modulus = BigNumber::Zero();
		publicExp = BigNumber::Zero();
	}
	if (this->privateKey != nullptr) {
		BigNumber p, q, dP, dQ, invQ;

		ippsRSA_GetPrivateKeyType2(p, q, dP, dQ, invQ, this->privateKey);

		std::cout << "P (" << p.BitSize() << ")" << std::endl;
		std::cout << p << std::endl << std::endl;

		std::cout << "Q (" << q.BitSize() << ")" << std::endl;
		std::cout << q << std::endl << std::endl;

		std::cout << "dP (" << dP.BitSize() << ")" << std::endl;
		std::cout << dP << std::endl << std::endl;

		std::cout << "dQ (" << dQ.BitSize() << ")" << std::endl;
		std::cout << dQ << std::endl << std::endl;

		std::cout << "invQ (" << invQ.BitSize() << ")" << std::endl;
		std::cout << invQ << std::endl << std::endl;

		p = BigNumber::Zero();
		q = BigNumber::Zero();
		dP = BigNumber::Zero();
		dQ = BigNumber::Zero();
		invQ = BigNumber::Zero();
	}

	std::cout << "-----------------------------------------------------------------------------------------" << std::endl;

}

ERR_STATUS ege::RSA_Crypt::readKeys(const std::string filepath)
{
	ERR_STATUS status = NO_ERROR;
	std::ifstream fptr(filepath, std::fstream::in);

	if (fptr.is_open()) {
		BigNumber modulus, publicExp, p, q;
		size_t flag[4] = { 0 };
		std::string line;
		std::getline(fptr, line);
		
		while (std::getline(fptr, line)) {
			if (line.find("Modulus (") != std::string::npos) {
				std::getline(fptr, line);
				modulus = BigNumber(line.c_str());				
				++flag[0];
			}
			else if (line.find("Public exponential (") != std::string::npos) {
				std::getline(fptr, line);
				publicExp = BigNumber(line.c_str());
				++flag[1];
			}
			else if (line.find("P (") != std::string::npos) {
				std::getline(fptr, line);
				p = BigNumber(line.c_str());
				++flag[2];
			}
			else if (line.find("Q (") != std::string::npos) {
				std::getline(fptr, line);
				q = BigNumber(line.c_str());
				++flag[3];
			}
		}

		if (flag[0] == 1 && flag[1] == 1) { // Public key supplied
			if (modulus.BitSize() != this->bitsize)
				return CRYPT_BITSIZE_MISMATCH;

			status = ippsRSA_SetPublicKey(modulus, publicExp, this->publicKey);
			if (status != NO_ERROR)
				return status;

			modulus = BigNumber::Zero();
			publicExp = BigNumber::Zero();
		}
		
		if (flag[2] == 1 && flag[3] == 1) { // Private key supplied
			if (p.BitSize() + q.BitSize() != this->bitsize)
				return CRYPT_BITSIZE_MISMATCH;

			BigNumber dP, dQ, invQ;
			status = ippsRSA_SetPrivateKeyType2(p, q, dP, dQ, invQ, this->privateKey);
			if (status != NO_ERROR)
				return status;

			this->bitsP = p.BitSize();
			this->bitsQ = q.BitSize();

			p = BigNumber::Zero();
			q = BigNumber::Zero();
			dP = BigNumber::Zero();
			dQ = BigNumber::Zero();
			invQ = BigNumber::Zero();
		}
	}

	return NO_ERROR;
}

ERR_STATUS ege::RSA_Crypt::saveKeys(const std::string filepath)
{
	ERR_STATUS status = NO_ERROR;
	fstream fptr(filepath, std::fstream::out | std::fstream::trunc);

	if (fptr.is_open()) {
		fptr << "-----------------------------------------------------------------------------------------" << std::endl;
		if (this->publicKey != nullptr) {
			BigNumber modulus, publicExp;

			status = ippsRSA_GetPublicKey(modulus, publicExp, this->publicKey);
			if (status != NO_ERROR)
				return status;

			fptr << "Modulus (" << modulus.BitSize() << ")" << std::endl;
			fptr << modulus << std::endl << std::endl;

			fptr << "Public exponential (" << publicExp.BitSize() << ")" << std::endl;
			fptr << publicExp << std::endl << std::endl;

			modulus = BigNumber::Zero();
			publicExp = BigNumber::Zero();
		}
		if (this->privateKey != nullptr) {
			BigNumber p, q;

			status = ippsRSA_GetPrivateKeyType2(p, q, nullptr, nullptr, nullptr, this->privateKey);
			if (status != NO_ERROR)
				return status;

			fptr << "P (" << p.BitSize() << ")" << std::endl;
			fptr << p << std::endl << std::endl;

			fptr << "Q (" << q.BitSize() << ")" << std::endl;
			fptr << q << std::endl << std::endl;

			p = BigNumber::Zero();
			q = BigNumber::Zero();
		}
		fptr << "-----------------------------------------------------------------------------------------" << std::endl;
		fptr.close();

		return NO_ERROR;
	}
	else {
		return ippStsNoOperation;
	}

}

ERR_STATUS ege::RSA_Crypt::encryptMessage(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, Ipp8u *label, int lenlabel)
{
	return ippsRSAEncrypt_OAEP(msg, lenmsg, label, lenlabel, (Ipp8u*)this->seed, ciphertext, this->publicKey, ippHashAlg_SHA512_256, this->buffer);
}

ERR_STATUS ege::RSA_Crypt::decryptMessage(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, Ipp8u *label, int lenlabel)
{
	return ippsRSADecrypt_OAEP(ciphertext, label, lenlabel, msg, &lenmsg, this->privateKey, ippHashAlg_SHA512_256, this->buffer);
}

ERR_STATUS ege::RSA_Crypt::getKey(int key_type, Ipp8u * key, int keysize)
{
	ERR_STATUS status = NO_ERROR;
	std::string buffer;
	size_t size;

	if (!key)
		return ippStsNullPtrErr;
	
	switch (key_type)
	{
	case IppRSApublic:
	{
		BigNumber modulus, publicExp;

		if (status = ippsRSA_GetPublicKey(modulus, publicExp, this->publicKey))
			return status;
		
		modulus.num2hex(buffer); 
		keysize -= buffer.size();
		if (keysize < 0)
			return ippStsLengthErr;
		memcpy(key, buffer.c_str(), buffer.size());

		size = buffer.size();

		publicExp.num2hex(buffer);
		keysize -= buffer.size();
		if (keysize < 0)
			return ippStsLengthErr;
		memcpy(&key[size], buffer.c_str(), buffer.size());
	}
	case IppRSAprivate:
	{
		BigNumber p, q;

		if (status = ippsRSA_GetPrivateKeyType2(p, q, nullptr, nullptr, nullptr, this->privateKey))
			return status;

		p.num2hex(buffer);
		keysize -= buffer.size();
		if (keysize < 0)
			return ippStsLengthErr;
		memcpy(key, buffer.c_str(), buffer.size());

		size = buffer.size();

		q.num2hex(buffer);
		keysize -= buffer.size();
		if (keysize < 0)
			return ippStsLengthErr;
		memcpy(&key[size], buffer.c_str(), buffer.size());
	}
	default:
		return CRYPT_UNKNOWN_KEY_TYPE;
	}

	return NO_ERROR;
}

ege::RSA_Crypt::~RSA_Crypt()
{
	int ctxSize;

	if (this->privateKey != nullptr) {	// Overwrite sensitive data
		ippsRSA_GetSizePrivateKeyType2(this->bitsP, this->bitsQ, &ctxSize);
		ippsRSA_InitPrivateKeyType2(this->bitsP, this->bitsQ, this->privateKey, ctxSize);
		delete[](Ipp8u*)this->privateKey;
		this->privateKey = nullptr;
	}

	if (this->publicKey != nullptr) {	// Overwrite sensitive data
		BigNumber modulus, exponent;
		ippsRSA_GetPublicKey(modulus, exponent, this->publicKey);
		ippsRSA_GetSizePublicKey(modulus.BitSize(), exponent.BitSize(), &ctxSize);
		ippsRSA_InitPublicKey(modulus.BitSize(), exponent.BitSize(), this->publicKey, ctxSize);

		modulus = BigNumber::Zero();
		exponent = BigNumber::Zero();
		delete[](Ipp8u*)this->publicKey;
		this->publicKey = nullptr;
	}

	delete[](Ipp8u*)this->buffer;
	delete[](Ipp8u*)this->pPG;
	delete[](Ipp8u*)this->pRNG;
	delete[] this->seed;
}

inline void ege::RSA_Crypt::generate_PrimeGenerator(int maxbits, IppsPrimeState *& pPG)
{
	ERR_STATUS status;
	int ctxSize;

	status = ippsPrimeGetSize(maxbits, &ctxSize);			// Get size
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	pPG = (IppsPrimeState*)(new Ipp8u[ctxSize]);			// Allocate
	status = ippsPrimeInit(maxbits, pPG);					// Init prime
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
}

inline void ege::RSA_Crypt::generate_RandomGenerator(int seedbits, IppsPRNGState *& pRNG, IppsBigNumState * seed)
{
	ERR_STATUS status = NO_ERROR;
	int ctxSize;

	status = ippsPRNGGetSize(&ctxSize);						// Get size
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	pRNG = (IppsPRNGState*)(new Ipp8u[ctxSize]);			// Allocate
	status = ippsPRNGInit(seedbits, pRNG);					// Init rand		
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));

	if (!seed) {
		status = ippsPRNGSetSeed(seed, pRNG);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
	}
	else {
		BigNumber seed(rand32(seedbits / 32), seedbits / 32, IppsBigNumPOS);
		status = ippsPRNGSetSeed(seed, pRNG);
		if (status != NO_ERROR)
			throw runtime_error(ege::sterror(status, IPP_ID));
	}
}

inline Ipp32u* ege::RSA_Crypt::rand32(int size)
{
	Ipp32u* pX = new Ipp32u[size];
	std::srand(std::time(nullptr)); // Seed with current time
	for (int n = 0; n < size; n++)
		pX[n] = (rand() << 16) + rand();
	return pX;
}

ege::AES_Crypt::AES_Crypt(Ipp8u* pkey)
{
	ERR_STATUS status = NO_ERROR;
	int ctxSize = 0;

	status = ippsAESGetSize(&ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	this->key = (IppsAESSpec*)(new Ipp8u[ctxSize]);
	this->ctr = new Ipp8u[16];

	if (pkey == nullptr) {
		pkey = rand8(256 / 8);
	}
	
	status = ippsAESInit(pkey, 256 / 8, this->key, ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
}

inline ERR_STATUS ege::AES_Crypt::setKey(Ipp8u * pkey)
{
	return ippsAESSetKey(pkey, 256 / 8, this->key);
}

ERR_STATUS ege::AES_Crypt::encryptMessage(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsAESEncryptCTR(msg, ciphertext, lenmsg, this->key, this->ctr, 16 * sizeof(Ipp8u));
	else
		return ippsAESEncryptCTR(msg, ciphertext, lenmsg, this->key, ctr, ctrBitLen);
}

ERR_STATUS ege::AES_Crypt::decryptMessage(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, Ipp8u *ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsAESDecryptCTR(ciphertext, msg, lenmsg, this->key, this->ctr, 16 * sizeof(Ipp8u));
	else
		return ippsAESDecryptCTR(ciphertext, msg, lenmsg, this->key, ctr, ctrBitLen);
}

ege::AES_Crypt::~AES_Crypt()
{
	if (this->key != nullptr) {
		int ctxSize;
		ippsAESGetSize(&ctxSize);
		ippsAESInit(nullptr, 256 / 8, key, ctxSize);
		delete[](Ipp8u*)this->key;
		this->key = nullptr;
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

inline ERR_STATUS ege::Hash_Coder::update(Ipp8u * msg, size_t lenmsg)
{
	return ippsHashUpdate(msg, lenmsg, this->context);
}

inline ERR_STATUS ege::Hash_Coder::getHash(Ipp8u *code)
{
	return ippsHashFinal(code, this->context);
}

ege::Hash_Coder::~Hash_Coder()
{
	delete[](Ipp8u*)this->context;
	this->context = nullptr;
}

ege::SMS4_Crypt::SMS4_Crypt(Ipp8u * pkey)
{
	ERR_STATUS status = NO_ERROR;
	int ctxSize = 0;

	status = ippsSMS4GetSize(&ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
	this->key = (IppsSMS4Spec*)(new Ipp8u[ctxSize]);
	this->ctr = new Ipp8u[16];

	if (pkey == nullptr) {
		pkey = rand8(256 / 8);
	}

	status = ippsSMS4Init(pkey, 256 / 8, key, ctxSize);
	if (status != NO_ERROR)
		throw runtime_error(ege::sterror(status, IPP_ID));
}

inline ERR_STATUS ege::SMS4_Crypt::setKey(Ipp8u * key)
{
	return ippsSMS4SetKey(key, 256 / 8, this->key);
}

ERR_STATUS ege::SMS4_Crypt::encryptMessage(Ipp8u *& msg, int lenmsg, Ipp8u *& ciphertext, Ipp8u * ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsSMS4EncryptCTR(msg, ciphertext, lenmsg, this->key, this->ctr, 16 * sizeof(Ipp8u));
	else
		return ippsSMS4EncryptCTR(msg, ciphertext, lenmsg, this->key, ctr, ctrBitLen);
}

ERR_STATUS ege::SMS4_Crypt::decryptMessage(Ipp8u *& ciphertext, Ipp8u *& msg, int & lenmsg, Ipp8u * ctr, int ctrBitLen)
{
	if (ctr == nullptr)
		return ippsSMS4DecryptCTR(ciphertext, msg, lenmsg, this->key, this->ctr, 16 * sizeof(Ipp8u));
	else
		return ippsSMS4DecryptCTR(ciphertext, msg, lenmsg, this->key, ctr, ctrBitLen);
}

ege::SMS4_Crypt::~SMS4_Crypt()
{
	if (this->key != nullptr) {
		int ctxSize;
		ippsSMS4GetSize(&ctxSize);
		ippsSMS4Init(nullptr, 256 / 8, key, ctxSize);
		delete[](Ipp8u*)this->key;
		this->key = nullptr;
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
