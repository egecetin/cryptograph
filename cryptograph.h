#pragma once

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
		void printKeys();
		ERR_STATUS readKeys(const std::string filepath);
		ERR_STATUS saveKeys(const std::string filepath);
		ERR_STATUS encryptMessage();
		ERR_STATUS decryptMessage();
		~RSA_Crypt();

	private:
		// Variables
		IppsPrimeState* pPG;
		IppsPRNGState* pRNG;
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
		AES_Crypt();
		~AES_Crypt();

	private:

	};

}