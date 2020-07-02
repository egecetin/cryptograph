#pragma once

#ifndef CRYPTOGRAPH_EGE
#define CRYPTOGRAPH_EGE
#endif

#include "logger.h"
#include "ippcp_bignumber.h"
#include <ippcp.h>
#include <string>

constexpr auto N_TRIAL = 10;
constexpr auto MAX_TRIAL = 25;
constexpr Ipp8u KNOWN_WORD[] = "The magic words are squeamish ossifrage";

#define MAX_HASH_LEN	64

namespace ege {
	
	/*******************************************************************************************/
	/*************************************** Definitions ***************************************/
	/*******************************************************************************************/

	enum CRYPTO_METHOD
	{
		NO_ENCRYPT,
		AES,
		SMS4,
		RSA,
		ECCP
	};

	/*******************************************************************************************/
	/****************************************** Class ******************************************/
	/*******************************************************************************************/
	

	/******************************************* RSA *******************************************/
	class RSA_Crypt
	{
	public:
		// Variables
		int bitsize = 0;

		// Functions
		RSA_Crypt(const int bitsize, Ipp8u *private_key = nullptr, size_t privateSize = 0, Ipp8u *public_key = nullptr, size_t publicSize = 0);
		ERR_STATUS setKey(int key_type, const Ipp8u *key, int keySize);
		ERR_STATUS encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *label = nullptr, int lenlabel = 0);
		ERR_STATUS decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *label = nullptr, int lenlabel = 0);
		ERR_STATUS getKey(int key_type, Ipp8u *key, int keysize);

#ifdef _DEBUG
		void printKeys();
		ERR_STATUS readKeys(const std::string filepath);
		ERR_STATUS saveKeys(const std::string filepath);
#endif
		~RSA_Crypt();

	private:
		// Variables
		IppsRSAPrivateKeyState *privateKey = nullptr;
		IppsRSAPublicKeyState *publicKey = nullptr;
		IppsPrimeState* pPG;
		IppsPRNGState* pRNG;
		Ipp32u* seed;
		Ipp8u* buffer;
		int bitsP, bitsQ;

		// Functions
		inline void generate_PrimeGenerator(int maxbits, IppsPrimeState*& pPG);
		inline void generate_RandomGenerator(int seedbits, IppsPRNGState*& pRNG, IppsBigNumState* seed = 0);
		inline Ipp32u* rand32(int size);
	};


	/************************************** Elliptic Curve **************************************/
	class ECCP_Crypt
	{
	public:
		ECCP_Crypt();
		~ECCP_Crypt();

	private:

	};


	/******************************************* AES *******************************************/
	class AES_Crypt // Only 256 bit
	{
	public:
		// Variables

		// Functions
		AES_Crypt(Ipp8u* pkey = nullptr);
		inline ERR_STATUS setKey(const Ipp8u* key);
		ERR_STATUS encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		ERR_STATUS decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		~AES_Crypt();

	private:
		// Variables
		IppsAESSpec* key = nullptr;
		Ipp8u* ctr = nullptr;

		// Functions
		inline Ipp8u* rand8(int size);
	};


	/******************************************* SMS4 *******************************************/
	class SMS4_Crypt // Only 256 bit
	{
	public:
		// Variables

		// Functions
		SMS4_Crypt(Ipp8u* pkey = nullptr);
		ERR_STATUS setKey(const Ipp8u* key);
		ERR_STATUS encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		ERR_STATUS decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		~SMS4_Crypt();

	private:
		// Variables
		IppsSMS4Spec* key = nullptr;
		Ipp8u* ctr = nullptr;

		// Functions
		inline Ipp8u* rand8(int size);
	};

	class Hash_Coder
	{
	public:
		Hash_Coder(IppHashAlgId id);
		ERR_STATUS update(Ipp8u* msg, size_t lenmsg);
		ERR_STATUS getHash(Ipp8u *code);
		~Hash_Coder();

	private:
		IppsHashState *context = nullptr;
	};

	/*******************************************************************************************/
	/**************************************** Functions ****************************************/
	/*******************************************************************************************/

}