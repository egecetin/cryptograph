#pragma once

#include "logger.h"
#include "ippcp_bignumber.h"
#include <ippcp.h>
#include <string>

constexpr Ipp8u KNOWN_WORD[] = "The magic words are squeamish ossifrage";

#define AES_CTR_SIZE	16	// Size of ctr context in bytes
#define SMS4_CTR_SIZE	16	// Size of ctr context in bytes
#define MAX_HASH_LEN	64

namespace ege {
	
	// #################################### Definitions #################################### //
	enum CRYPTO_METHOD
	{
		NO_ENCRYPT,
		AES,
		SMS4,
		CRYPTO_METHOD_MAX
	};

	class AES_Crypt // Only 256 bit
	{
	public:
		// Variables

		// Functions
		AES_Crypt(Ipp8u* pkey = nullptr, size_t keyLen = 256);
		ERR_STATUS setKey(const Ipp8u* key, size_t keyLen);
		ERR_STATUS encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		ERR_STATUS decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		~AES_Crypt();

	private:
		// Variables
		size_t keyLen = 0;
		IppsAESSpec* key = nullptr;
		Ipp8u* ctr = nullptr;

		// Functions
		inline Ipp8u* rand8(int size);
	};

	class SMS4_Crypt // Only 256 bit
	{
	public:
		// Variables

		// Functions
		SMS4_Crypt(Ipp8u* pkey = nullptr, size_t keyLen = 256);
		ERR_STATUS setKey(const Ipp8u* key, size_t keyLen);
		ERR_STATUS encryptMessage(const Ipp8u *msg, int lenmsg, Ipp8u *ciphertext, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		ERR_STATUS decryptMessage(const Ipp8u *ciphertext, Ipp8u *msg, int &lenmsg, Ipp8u *ctr = nullptr, int ctrBitLen = 0);
		~SMS4_Crypt();

	private:
		// Variables
		size_t keyLen = 0;
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

}