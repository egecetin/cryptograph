#pragma once

#include <string>

#include "ege_error.h"
#include "ippcp_bignumber.h"
#include <ippcp.h>

constexpr auto N_TRIAL = 10;
constexpr auto MAX_TRIAL = 25;

namespace ege {
	
	class RSA_Crypt
	{
	public:
		// Variables
		IppsRSAPrivateKeyState *privateKey = nullptr;
		IppsRSAPublicKeyState *publicKey = nullptr;
		int bitsize = 0;

		// Functions
		RSA_Crypt(const int bitsize, Ipp32u *private_key = nullptr, size_t privateSize = 0, Ipp32u *public_key = nullptr, size_t publicSize = 0);
		ERR_STATUS encryptMessage(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, Ipp8u *label = nullptr, int lenlabel = 0);
		ERR_STATUS decryptMessage(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, Ipp8u *label = nullptr, int lenlabel = 0);

		// Only for Debug
		void printKeys();
		ERR_STATUS readKeys(const std::string filepath);
		ERR_STATUS saveKeys(const std::string filepath);

		~RSA_Crypt();

	private:
		// Variables
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

	class ECCP_Crypt
	{
	public:
		ECCP_Crypt();
		~ECCP_Crypt();

	private:

	};

	class AES_Crypt
	{
	public:
		// Variables
		IppsAESSpec* key = nullptr;

		// Functions
		AES_Crypt(Ipp8u* key = nullptr);
		ERR_STATUS encrypt(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		ERR_STATUS decrypt(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		~AES_Crypt();

	private:
		// Variables
		Ipp8u* ctr = nullptr;

		// Functions
		inline Ipp8u* rand8(int size);
	};

}