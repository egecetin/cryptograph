#pragma once

#include "ege_error.h"
#include "ippcp_bignumber.h"

#include <ippcp.h>

#ifdef _WIN32
#include <Windows.h>
#endif // _WIN32

namespace ege {

	// RSA
	ERR_STATUS RSA_Init(int bitsize, IppsRSAPrivateKeyState*& private_key, IppsRSAPublicKeyState*& public_key, int nTrials = 1);
	ERR_STATUS RSA_DeInit(IppsRSAPrivateKeyState*& private_key, IppsRSAPublicKeyState*& public_key);

	ERR_STATUS RSA_Encrypt(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, Ipp8u *label = NULL, int labellen = 0);
	//inline ERR_STATUS RSA_Encrypt_SharedMem(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, Ipp8u *&seed, Ipp8u *&buffer);
	ERR_STATUS RSA_Encrypt_WCheck(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, IppsRSAPrivateKeyState *&private_key, Ipp8u *label = NULL, int lenlabel = 0);
	
	ERR_STATUS RSA_Decrypt(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, IppsRSAPrivateKeyState *&private_key, Ipp8u *label = NULL, int lenlabel = 0);
	//inline ERR_STATUS RSA_Decrypt_SharedMem(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, IppsRSAPrivateKeyState *&private_key, Ipp8u *&buffer);

	ERR_STATUS RSA_EncryptFile(IppsRSAPublicKeyState *&public_key, char *&path, char *&dest);
	
	// Elliptic curve
	ERR_STATUS ECCP_StdInit(IppsECCPState*& key, IppsBigNumState*& private_key, IppsECCPPointState*& public_key, IppsECCPPointState*& base_point);
	ERR_STATUS ECCP_DeInit(IppsECCPState*& key, IppsBigNumState*& private_key, IppsECCPPointState*& public_key, IppsECCPPointState*& base_point);

	ERR_STATUS ECCP_Encrypt(Ipp8u *&msg, int &len, Ipp8u *&ciphertext, IppsECCPState *&key, IppsECCPPointState *&public_key, IppsECCPPointState *&base_point);
	ERR_STATUS ECCP_Decrypt(Ipp8u *&ciphertext, int &len, Ipp8u *&msg, IppsECCPState *&key, IppsBigNumState *&private_key, IppsECCPPointState *&base_point);

	// AES
	ERR_STATUS AES_Init(IppsAESSpec*& key, Ipp8u *pkey = NULL);
	ERR_STATUS AES_DeInit(IppsAESSpec*& key);

	ERR_STATUS AES_EncryptFile(IppsAESSpec *&key, char *&path, char *&dest);

	// Prime Number Generator
	ERR_STATUS generate_PrimeGenerator(int size, IppsPrimeState*& pPG);
	inline void delete_PrimeGenerator(IppsPrimeState* pPG);

	// Random Generator
	ERR_STATUS generate_RandomGenerator(int size, IppsPRNGState*& pRNG, IppsBigNumState* sourceBN = 0);
	inline void delete_RandomGenerator(IppsPRNGState* pRNG);

	// Big Number
	ERR_STATUS generate_BigNumState(int size, IppsBigNumState*& pBN, bool rand_set = false);
	inline void delete_BigNumState(IppsBigNumState* pBN);
	inline void sqrt_BigNumState(IppsBigNumState* pBN, IppsBigNumState *pR);

	// Helper
	inline Ipp32u* rand32(Ipp32u* pX, int size);
	inline Ipp8u* rand8(Ipp8u* pX, int size);
	inline size_t getFileSize(FILE *&pFile);

	#ifdef _WIN32
	// WinAPI Functions


	#endif // _WIN32
}
