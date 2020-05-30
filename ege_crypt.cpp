#include "ege_crypt.h"

namespace ege {

	ERR_STATUS RSA_Init(int bitsize, IppsRSAPrivateKeyState*& private_key, IppsRSAPublicKeyState*& public_key, int nTrials) {

		ERR_STATUS status = ippStsNoErr;
		BigNumber sourceBN, sourcePExp, modulus, public_exp, private_exp;
		IppsBigNumState* pBN = NULL;
		IppsPRNGState* rand_gen = NULL;
		IppsPrimeState* prime_gen = NULL;
		Ipp8u* buffer8 = NULL;
		int ctxSize, bitsP = (bitsize + 1) / 2, bitsQ = bitsize - bitsP;

		// Big numbers
		status = generate_BigNumState(bitsize / 32, pBN, true);		// Generate random source
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		sourceBN = pBN; delete_BigNumState(pBN);

		status = generate_BigNumState(1, pBN, true);				// Source public exponential
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		sourcePExp = pBN; delete_BigNumState(pBN);

		status = generate_BigNumState(bitsize / 32, pBN, true);		// Modulus
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		modulus = pBN; delete_BigNumState(pBN);

		status = generate_BigNumState(bitsize / 32, pBN, true);		// Public exponential
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		public_exp = pBN; delete_BigNumState(pBN);

		status = generate_BigNumState(bitsize / 32, pBN, true);		// Private exponential
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		private_exp = pBN; delete_BigNumState(pBN);

		// Random number generator
		status = generate_RandomGenerator(160, rand_gen, sourceBN);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Prime number generator
		status = generate_PrimeGenerator(bitsize, prime_gen);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Init Private key
		status = ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		private_key = (IppsRSAPrivateKeyState*)(new (std::nothrow) Ipp8u[ctxSize]);
		if (private_key == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		status = ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, private_key, ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		
		status = ippsRSA_GetBufferSizePrivateKey(&ctxSize, private_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		buffer8 = new (std::nothrow) Ipp8u[ctxSize * 8];
		if (buffer8 == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		// Generate keys for RSA
		do {
			status = ippsRSA_GenerateKeys(sourcePExp, modulus, public_exp, private_exp, private_key, buffer8, nTrials, prime_gen, ippsPRNGen, rand_gen);
		} while (status == ippStsInsufficientEntropy);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Init Public key		
		status = ippsRSA_GetSizePublicKey(modulus.BitSize(), public_exp.BitSize(), &ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		public_key = (IppsRSAPublicKeyState*)(new (std::nothrow) Ipp8u[ctxSize]);
		if (public_key == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = ippsRSA_InitPublicKey(modulus.BitSize(), public_exp.BitSize(), public_key, ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsRSA_SetPublicKey(modulus, public_exp, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Validate keys
		status = ippsRSA_ValidateKeys(&ctxSize, public_key, private_key, NULL, buffer8, nTrials, prime_gen, ippsPRNGen, rand_gen);
		if (ctxSize == IS_INVALID_KEY) {
			status = ippStsContextMatchErr;
		}

		#ifdef _DEBUG
			std::cout << "-----------------------------------------------------------------------------------------" << std::endl;
			std::cout << "Modulus (" << modulus.BitSize() << ")" << std::endl;
			std::cout << modulus << std::endl << std::endl;

			std::cout << "Public exponential (" << public_exp.BitSize() << ")" << std::endl;
			std::cout << public_exp << std::endl << std::endl;

			std::cout << "Private exponential (" << private_exp.BitSize() << ")" << std::endl;
			std::cout << private_exp << std::endl << std::endl;
		#endif // _DEBUG		

	cleanup:;
		delete_RandomGenerator(rand_gen);
		delete_PrimeGenerator(prime_gen);

		delete[] buffer8;
		if (status != ippStsNoErr) {
			delete[](Ipp8u*)private_key; private_key = NULL;
			delete[](Ipp8u*)public_key; public_key = NULL;
		}

		return status;
	}

	ERR_STATUS RSA_DeInit(IppsRSAPrivateKeyState*& private_key, IppsRSAPublicKeyState*& public_key) {
		
		ERR_STATUS status = ippStsNoErr;
		BigNumber modulus, exponent;
		int ctxSize;

		if (private_key != NULL) {

			status = ippsRSA_GetPrivateKeyType2(modulus, exponent, NULL, NULL, NULL, private_key);
			if (status != ippStsNoErr) {
				return status;
			}

			status = ippsRSA_GetSizePrivateKeyType2(modulus.BitSize(), exponent.BitSize(), &ctxSize);
			if (status != ippStsNoErr) {
				return status;
			}

			status = ippsRSA_InitPrivateKeyType2(modulus.BitSize(), exponent.BitSize(), private_key, ctxSize);
			if (status != ippStsNoErr) {
				return status;
			}

			modulus = modulus.Zero();
			exponent = exponent.Zero();
			delete[](Ipp8u*)private_key; private_key = NULL;
		}

		if (public_key != NULL) {

			status = ippsRSA_GetPublicKey(modulus, exponent, public_key);
			if (status != ippStsNoErr) {
				return status;
			}

			status = ippsRSA_GetSizePublicKey(modulus.BitSize(), exponent.BitSize(), &ctxSize);
			if (status != ippStsNoErr) {
				return status;
			}

			status = ippsRSA_InitPublicKey(modulus.BitSize(), exponent.BitSize(), public_key, ctxSize);
			if (status != ippStsNoErr) {
				return status;
			}

			modulus = modulus.Zero();
			exponent = exponent.Zero();
			delete[](Ipp8u*)public_key; public_key = NULL;
		}

		return status;
	}

	ERR_STATUS RSA_Encrypt(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, Ipp8u *label, int lenlabel) {

		int size;
		ERR_STATUS status = ippStsNoErr;
		Ipp8u *buffer = NULL;
		Ipp8u *seed = new (std::nothrow) Ipp8u[256];

		// Generate seed
		if (seed == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		rand8(seed, 256);

		// Get buffer size
		status = ippsRSA_GetBufferSizePublicKey(&size, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		buffer = new (std::nothrow) Ipp8u[size];
		if (buffer == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		// Encrypt (OAEP)
		status = ippsRSAEncrypt_OAEP(msg, lenmsg, label, lenlabel, seed, ciphertext, public_key, ippHashAlg_SHA512_256, buffer);

	cleanup:;
		delete[] buffer;
		delete[] seed;

		return status;
	}

	/*
	inline ERR_STATUS RSA_Encrypt_SharedMem(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, Ipp8u *&seed, Ipp8u *&buffer) {
		return ippsRSAEncrypt_OAEP(msg, lenmsg, NULL, 0, seed, ciphertext, public_key, ippHashAlg_SHA512_256, buffer);
	}
	*/
	
	ERR_STATUS RSA_Encrypt_WCheck(Ipp8u *&msg, int lenmsg, Ipp8u *&ciphertext, IppsRSAPublicKeyState *&public_key, IppsRSAPrivateKeyState *&private_key, Ipp8u *label, int lenlabel) {

		ERR_STATUS status = ippStsNoErr;
		int lenbuffmsg = 0, lenbufflabel = 0;
		Ipp8u *buffmsg = new (std::nothrow) Ipp8u[lenmsg];
		Ipp8u *bufflabel = new (std::nothrow) Ipp8u[lenlabel];
		if (buffmsg == NULL || bufflabel == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		// Encrypt
		status = RSA_Encrypt(msg, lenmsg, ciphertext, public_key, label, lenlabel);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Decrypt
		status = RSA_Decrypt(ciphertext, buffmsg, lenbuffmsg, private_key, bufflabel, lenbufflabel);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Check
		if (lenmsg == lenbuffmsg) {
			ippsCompare_8u(msg, buffmsg, lenmsg, &status);
			if (status != ippStsNoErr)
				status = ippStsErr;
		}
		else
			status = ippStsErr;

	cleanup:;

		delete[] buffmsg;
		delete[] bufflabel;

		return status;
	}

	ERR_STATUS RSA_Decrypt(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, IppsRSAPrivateKeyState *&private_key, Ipp8u *label, int lenlabel) {

		ERR_STATUS status = ippStsNoErr;
		Ipp8u *buffer = NULL;
		int size;

		status = ippsRSA_GetBufferSizePrivateKey(&size, private_key);
		if (status != ippStsNoErr) {
			return status;
		}
		buffer = new (std::nothrow) Ipp8u[size];
		if (buffer == NULL) {
			status = ippStsMemAllocErr;
			delete[] buffer;
			return status;
			
		}
		status = ippsRSADecrypt_OAEP(ciphertext, label, lenlabel, msg, &lenmsg, private_key, ippHashAlg_SHA512_256, buffer);

		delete[] buffer;
		return status;
	}

	/*
	inline ERR_STATUS RSA_Decrypt_SharedMem(Ipp8u *&ciphertext, Ipp8u *&msg, int &lenmsg, IppsRSAPrivateKeyState *&private_key, Ipp8u *&buffer) {
		return ippsRSADecrypt_OAEP(ciphertext, NULL, 0, msg, &lenmsg, private_key, ippHashAlg_SHA512_256, buffer);
	}
	*/

	ERR_STATUS RSA_EncryptFile(IppsRSAPublicKeyState *&public_key, char *&path, char *&dest) {
		
		// Init
		ERR_STATUS status = ippStsNoErr;
		size_t msglen, cipherlen, filesize;
		int size;

		BigNumber modulus;
		Ipp8u *buff = NULL, *seed = NULL;
		Ipp8u *msg = NULL, *cipher = NULL;
		IppsBigNumState *pBN = NULL;		
		char *buff2 = NULL, *ptr = NULL;

		std::vector<char*> filelist;
		FILE *prFile = NULL, *pwFile = NULL;		
		
		// Open file
	#ifdef _WIN32
		if (!fopen_s(&pwFile, path, "wb")) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#else
		pwFile = fopen(path, "wb");
		if (!prFile) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#endif // _WIN32

		// Allocate buffers
		status = ege::generate_BigNumState(MAX_RSA_SIZE / 32, pBN, true);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		modulus = pBN;

		status = ippsRSA_GetPublicKey(modulus, NULL, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		msglen = modulus.BitSize() / 8 - 512 / 4 - 2; // mLen = k - 2 * hLen - 2
		cipherlen = modulus.BitSize() / 8;
		modulus.One();
		cipher = new (std::nothrow) unsigned char[cipherlen];
		msg = new (std::nothrow) unsigned char[msglen];
		buff2 = new (std::nothrow) char[64];
		seed = new (std::nothrow) Ipp8u[256];
		if (!(cipher && msg && buff2 && seed)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		rand8(seed, 256);

		status = ippsRSA_GetBufferSizePublicKey(&size, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		buff = new (std::nothrow) Ipp8u[size];
		if (buff == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		// Write codeword
		status = fwrite("ege!", sizeof(char) * 4, 1, pwFile);
		if (status != 4) {
			status = ippStsErr;
			goto cleanup;
		}

		// Encrypt compression
		msg[0] = 78; msg[1] = 79; msg[2] = 78; msg[3] = 69; // "none"
		//status = RSA_Encrypt_SharedMem(msg, 4, cipher, public_key, seed, buff);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
		if (status != cipherlen) {
			status = ippStsErr;
			goto cleanup;
		}

		/*
		// Open files
	#ifdef _WIN32
		if (!(fopen_s(&prFile, path, "rb") && fopen_s(&pwFile, dest, "wb"))) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#else
		prFile = fopen(path, "rb");
		pwFile = fopen(dest, "wb");
		if (!(prFile && pwFile)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#endif // _WIN32
		
		// Allocate buffers
		status = ege::generate_BigNumState(MAX_RSA_SIZE / 32, pBN, true);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		modulus = pBN;

		status = ippsRSA_GetPublicKey(modulus, NULL, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		
		msglen = modulus.BitSize() / 8 - 512 / 4 - 2; // mLen = k - 2 * hLen - 2
		cipherlen = modulus.BitSize() / 8; 
		modulus.One();
		cipher = new unsigned char[cipherlen];
		msg = new unsigned char[msglen];
		buff2 = new char[64];
		seed = new Ipp8u[256];
		if (!(cipher && msg && buff2 && seed)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		rand8(seed, 256);

		status = ippsRSA_GetBufferSizePublicKey(&size, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		buff = new Ipp8u[size];
		
		// Write codeword
		status = fwrite("ege!", sizeof(char) * 4, 1, pwFile);
		if (status != 4) {
			status = ippStsErr;
			goto cleanup;
		}
		
		// Encrypt compression
		msg[0] = 78; msg[1] = 79; msg[2] = 78; msg[3] = 69; // "none"
		status = RSA_Encrypt_SharedMem(msg, 4, cipher, public_key, seed, buff);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
		if (status != cipherlen) {
			status = ippStsErr;
			goto cleanup;
		}

		// Encrypt filename.extension
		ptr = strrchr(path, '\\');
		if (ptr == NULL) {
			ptr = strrchr(path, '/');
			if (ptr == NULL) {
				status = ippStsErr;
				goto cleanup;
			}
		}
		size = strlen(ptr);

		if (size > msglen) { // If filename.ext is longer than max msg length
			for (size_t i = 0; i < size / (msglen + 1); ++i) {
				Ipp8s *bff = (Ipp8s*)ptr + i * msglen;
				status = ippsConvert_8s8u(bff, msg, msglen);
				if (status != ippStsNoErr) {
					goto cleanup;
				}
				status = RSA_Encrypt_SharedMem(msg, msglen, cipher, public_key, seed, buff);
				if (status != ippStsNoErr) {
					goto cleanup;
				}
				status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
				if (status != cipherlen) {
					status = ippStsErr;
					goto cleanup;
				}
			}
		}
		else {
			status = ippsConvert_8s8u((Ipp8s*)ptr, msg, size);
			if (status != ippStsNoErr) {
				goto cleanup;
			}
			status = RSA_Encrypt_SharedMem(msg, size, cipher, public_key, seed, buff);
			if (status != ippStsNoErr) {
				goto cleanup;
			}
			status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
			if (status != cipherlen) {
				status = ippStsErr;
				goto cleanup;
			}
		}

		// Encrypt size
		filesize = getFileSize(prFile);
	#ifdef _WIN32
		size = sprintf_s(buff2, 64, "%d");
		if (size == -1) {
			status = ippStsErr;
			goto cleanup;
		}
	#else
		size = sprintf(buff2, "%d");
		if (size < 0) {
			status = ippStsErr;
			goto cleanup;
		}
	#endif // _WIN32
		
		if (size > msglen) { // If filesize is longer than max msg length
			for (size_t i = 0; i < size / (msglen + 1); ++i) {
				Ipp8s *bff = (Ipp8s*)buff2 + i * msglen;
				status = ippsConvert_8s8u(bff, msg, msglen);
				if (status != ippStsNoErr) {
					goto cleanup;
				}
				status = RSA_Encrypt_SharedMem(msg, msglen, cipher, public_key, seed, buff);
				if (status != ippStsNoErr) {
					goto cleanup;
				}
				status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
				if (status != cipherlen) {
					status = ippStsErr;
					goto cleanup;
				}
			}
		}
		else {
			status = ippsConvert_8s8u((Ipp8s*)buff2, msg, size);
			if (status != ippStsNoErr) {
				goto cleanup;
			}
			status = RSA_Encrypt_SharedMem(msg, size, cipher, public_key, seed, buff);
			if (status != ippStsNoErr) {
				goto cleanup;
			}
			status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
			if (status != cipherlen) {
				status = ippStsErr;
				goto cleanup;
			}
		}

		// Encrypt file
		while (!feof(prFile)) {

		#ifdef _WIN32
			size_t rlen = fread_s(msg, msglen * sizeof(unsigned char), sizeof(unsigned char), msglen, prFile);
		#else
			size_t rlen = fread(msg, sizeof(unsigned char), msglen, prFile);
		#endif // _WIN32

			status = RSA_Encrypt_SharedMem(msg, rlen, cipher, public_key, seed, buff);
			if (status != ippStsNoErr) {				
				break;
			}
			status = fwrite(cipher, sizeof(unsigned char)*cipherlen, 1, pwFile);
			if (status != cipherlen) {
				status = ippStsErr;
				break;
			}
		}
		*/
	cleanup:;
		delete_BigNumState(pBN);		
		delete[] cipher;
		delete[] msg;
		delete[] buff;
		delete[] buff2;
		delete[] seed;

		fclose(prFile);
		fclose(pwFile);
		if (status != ippStsNoErr) {
			remove(dest);
		}

		return status;
	}

	ERR_STATUS AES_Init(IppsAESSpec*& key, Ipp8u *pkey) {

		ERR_STATUS status = ippStsNoErr;
		int ctxSize = 0;

		status = ippsAESGetSize(&ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		key = (IppsAESSpec*)(new (std::nothrow) Ipp8u[ctxSize]);
		if (pkey == NULL) {
			pkey = new (std::nothrow) Ipp8u[256 / 8];
			rand8(pkey, 256 / 8);
		}
		if (key == NULL || pkey == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		
		status = ippsAESInit(pkey, 256 / 8, key, ctxSize);

	cleanup:;
		if (status != ippStsNoErr) {
			delete[](Ipp8u*)key; key = NULL;
		}
		delete[] pkey;		
		return status;
	}

	ERR_STATUS AES_DeInit(IppsAESSpec*& key) {

		ERR_STATUS status = ippStsNoErr;
		int ctxSize = 0;

		status = ippsAESGetSize(&ctxSize);
		if (status != ippStsNoErr) {
			return status;
		}

		status = ippsAESInit(NULL, 256 / 8, key, ctxSize);
		if (status != ippStsNoErr) {
			return status;
		}

		delete[](Ipp8u*)key; key = NULL;

		return status;		
	}

	ERR_STATUS AES_EncryptFile(IppsAESSpec *&key, char *&path, char *&dest) {
		
		ERR_STATUS status;
		int leng = 3;
		Ipp8u deneme[] = "DE";
		Ipp8u *out = new Ipp8u[leng];
		Ipp8u *out2 = new Ipp8u[leng];
		Ipp8u x1[] = "1";
		Ipp8u x2[] = "1";

		status = ippsAESEncryptCTR(deneme, out, leng, key, x1, 16);
		for (size_t i = 0; i < leng; ++i)
			std::cout << deneme[i] << " ";
		std::cout << std::endl;

		status = ippsAESDecryptCTR(out, out2, leng, key, x2, 16);
		for (size_t i = 0; i < leng; ++i)
			std::cout << out2[i] << " ";
		std::cout << std::endl;

		return 0;
	}

	ERR_STATUS ECCP_StdInit(IppsECCPState*& key, IppsBigNumState*& private_key, IppsECCPPointState*& public_key, IppsECCPPointState *&base_point) {

		ERR_STATUS status = ippStsNoErr;
		IppsPRNGState* rand_gen = NULL;
		IppsBigNumState *pBN = NULL, *Gx = NULL, *Gy = NULL;
		IppECResult result;
		int ctxSize;
		
		// Random number generator
		status = generate_BigNumState(521 / 8, pBN, true);	// Generate random source
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = generate_RandomGenerator(160, rand_gen, pBN);
		if (status != ippStsNoErr) {
			goto cleanup;
		}


		// Init ECCP Context
		status = ippsECCPGetSizeStd521r1(&ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		key = (IppsECCPState*)new (std::nothrow) Ipp8u[ctxSize];
		if (key == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = ippsECCPInitStd521r1(key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPSetStd521r1(key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPBindGxyTblStd521r1(key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPValidate(10, &result, key, ippsPRNGen, rand_gen);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		if (result != ippECValid) {
			status = ippStsContextMatchErr;
			goto cleanup;
		}

		// Init public key
		status = ippsECCPPointGetSize(521, &ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		public_key = (IppsECCPPointState*)new (std::nothrow) Ipp8u[ctxSize];
		if (public_key == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = ippsECCPPointInit(521, public_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}


		// Init private key
		status = generate_BigNumState(521 / 8, private_key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}


		// Generate keys
		status = ippsECCPGenKeyPair(private_key, public_key, key, ippsPRNGen, rand_gen);
		if (status != ippStsNoErr) {
			goto cleanup;
		}


		// Validate keys
		status = ippsECCPValidateKeyPair(private_key, public_key, &result, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		if (result != ippECValid) {
			status = ippStsContextMatchErr;
		}
		
		// Get base point (G)
		status = generate_BigNumState(521 / 8, Gx);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = generate_BigNumState(521 / 8, Gy);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		
		status = ippsECCPGet(pBN, pBN, pBN, Gx, Gy, pBN, &ctxSize, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Set structure
		status = ippsECCPPointGetSize(521, &ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		base_point = (IppsECCPPointState*)new (std::nothrow) Ipp8u[ctxSize];
		if (base_point == NULL) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = ippsECCPPointInit(521, base_point);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPSetPoint(Gx, Gy, base_point, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

	cleanup:;
		ctxSize = 0;
		delete_RandomGenerator(rand_gen);
		delete_BigNumState(pBN);
		delete_BigNumState(Gx);
		delete_BigNumState(Gy);

		if (status != ippStsNoErr) {
			delete[](Ipp8u*)public_key; public_key = NULL;
			delete[](Ipp8u*)private_key; private_key = NULL;
			delete[](Ipp8u*)key; key = NULL;
			delete[](Ipp8u*)base_point; base_point = NULL;
		}

		return status;
	}

	ERR_STATUS ECCP_DeInit(IppsECCPState*& key, IppsBigNumState*& private_key, IppsECCPPointState*& public_key, IppsECCPPointState*& base_point) {

		ERR_STATUS status = ippStsNoErr;

		if (key != NULL) {			
			status = ippsECCPInitStd521r1(key);
			if (status != ippStsNoErr) {
				return status;
			}

			delete[](Ipp8u*)key; key = NULL;
		}
		
		if (private_key != NULL) {
			Ipp32u* pBuffer = new Ipp32u[521 / 8];
			status = ippsSet_BN(IppsBigNumPOS, 521 / 8, rand32(pBuffer, 521 / 8), private_key);
			if (status != ippStsNoErr) {
				return status;
			}

			delete[] pBuffer;
			delete[](Ipp8u*)private_key; private_key = NULL;
		}

		if (public_key != NULL) {
			status = ippsECCPPointInit(521, public_key);
			if (status != ippStsNoErr) {
				return status;
			}

			delete[](Ipp8u*)public_key; public_key = NULL;
		}

		if (base_point != NULL) {
			status = ippsECCPPointInit(521, base_point);
			if (status != ippStsNoErr) {
				return status;
			}
			
			delete[](Ipp8u*)base_point; base_point = NULL;
		}

		return status;
	}

	ERR_STATUS ECCP_Encrypt(Ipp8u *&msg, int &len, Ipp8u *&ciphertext, IppsECCPState *&key, IppsECCPPointState *&public_key, IppsECCPPointState *&base_point) {

		ERR_STATUS status = ippStsNoErr;
		IppsBigNumState *seed = NULL;
		BigNumber A, B, X, Y, P, XB;
		IppsECCPPointState *msgPoint = NULL, *C1 = NULL, *C2 = NULL;
		int ctxSize;
		
		status = generate_BigNumState(66, seed, true);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Get curve parameters

		// Set X and Y coordinates
		X.Set((Ipp32u*)msg, len);
		
		XB = X % P;
		A = A % P;
		B = B % P;

		Y = ((((XB*XB) % P)*XB) % P + A * XB + B) % P;
		sqrt_BigNumState(Y, Y);

		// Set points
		status = ippsECCPPointGetSize(521, &ctxSize);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		msgPoint = (IppsECCPPointState*)new (std::nothrow) Ipp8u[ctxSize];
		C1 = (IppsECCPPointState*)new (std::nothrow) Ipp8u[ctxSize];
		C2 = (IppsECCPPointState*)new (std::nothrow) Ipp8u[ctxSize];
		ciphertext = new (std::nothrow) Ipp8u[ctxSize * 2];
		if (!(msgPoint && C1 && C2 && ciphertext)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = ippsECCPPointInit(521, msgPoint);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPPointInit(521, C1);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPPointInit(521, C2);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPSetPoint(X, Y, msgPoint, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		// Encrypt message
		status = ippsECCPAddPoint(msgPoint, public_key, C1, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPMulPointScalar(base_point, seed, C2, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}
		
		// Copy to ciphertext
	#ifdef _WIN32
		if (memcpy_s(ciphertext, ctxSize, C1, ctxSize)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		if (memcpy_s(&ciphertext[ctxSize], ctxSize, C2, ctxSize)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#else
		memcpy(ciphertext, C1, ctxSize);
		memcpy(&ciphertext[ctxSize], C2, ctxSize);
	#endif // _WIN32

		len = 2 * ctxSize;
	cleanup:;

		delete_BigNumState(seed);

		if (status != ippStsNoErr) {
			delete[] ciphertext; ciphertext = NULL;
		}

		delete[](Ipp8u*)C1;
		delete[](Ipp8u*)C2;
		delete[](Ipp8u*)msgPoint;
		
		return status;

	
	}

	ERR_STATUS ECCP_Decrypt(Ipp8u *&ciphertext, int &len, Ipp8u *&msg, IppsECCPState *&key, IppsBigNumState *&private_key, IppsECCPPointState *&base_point) {

		ERR_STATUS status = ippStsNoErr;
		IppsECCPPointState *C1 = NULL, *C2 = NULL;
		IppsBigNumState *pX = NULL, *pY = NULL;
		int ctxSize;

		C1 = (IppsECCPPointState*)new (std::nothrow) Ipp8u[len/2];
		C2 = (IppsECCPPointState*)new (std::nothrow) Ipp8u[len/2];
		msg = new (std::nothrow) Ipp8u[521 / 8];
		if (!(C1 && C2 && msg)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}

		status = generate_BigNumState(521 / 8, pX);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = generate_BigNumState(521 / 8, pY);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

	#ifdef _WIN32
		if (memcpy_s(C1, len / 2, ciphertext, len / 2)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
		if (memcpy_s(C2, len / 2, &ciphertext[len / 2], len / 2)) {
			status = ippStsMemAllocErr;
			goto cleanup;
		}
	#else
		memcpy(C1, ciphertext, len / 2);
		memcpy(C2, &ciphertext[len / 2], len / 2);
	#endif // _WIN32

		status = ippsECCPMulPointScalar(C2, private_key, C2, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPNegativePoint(C2, C2, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPAddPoint(C1, C2, C1, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsECCPGetPoint(pX, pY, C1, key);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		status = ippsExtGet_BN(NULL, &ctxSize, (Ipp32u*)msg, pX);
		if (status != ippStsNoErr) {
			goto cleanup;
		}

		len = ctxSize / 8;

	cleanup:;

		delete_BigNumState(pX);
		delete_BigNumState(pY);

		if (status != ippStsNoErr) {
			delete[] msg;
		}
		
		delete[](Ipp8u*)C1;
		delete[](Ipp8u*)C2;

		return status;
	}

	ERR_STATUS generate_PrimeGenerator(int maxbits, IppsPrimeState*& pPG) {
		
		ERR_STATUS status;
		int ctxSize;
		
		status = ippsPrimeGetSize(maxbits, &ctxSize);				// Get size
		if (status != ippStsNoErr)
			return status;
		pPG = (IppsPrimeState*)(new (std::nothrow) Ipp8u[ctxSize]);	// Allocate
		if (pPG == NULL)
			return ippStsMemAllocErr;
		status = ippsPrimeInit(maxbits, pPG);						// Init prime															

		return status;
	}

	inline void delete_PrimeGenerator(IppsPrimeState* pPG) {
		delete[](Ipp8u*)pPG;
	}

	ERR_STATUS generate_RandomGenerator(int seedbits, IppsPRNGState*& pRNG, IppsBigNumState* sourceBN) {
		
		ERR_STATUS status = ippStsNoErr;
		int ctxSize;
		 
		status = ippsPRNGGetSize(&ctxSize);							// Get size
		if (status != ippStsNoErr)
			return status;		
		pRNG = (IppsPRNGState*)(new (std::nothrow) Ipp8u[ctxSize]);	// Allocate
		if (pRNG == NULL)
			return ippStsMemAllocErr;
		status = ippsPRNGInit(seedbits, pRNG);						// Init rand		
		if (status != ippStsNoErr)
			return status;
		
		if (!sourceBN)
			status = ippsPRNGSetSeed(sourceBN, pRNG);				// Set seed		

		return status;
	}

	inline void delete_RandomGenerator(IppsPRNGState* pRNG) {
		delete[](Ipp8u*)pRNG;
	}

	ERR_STATUS generate_BigNumState(int size, IppsBigNumState*& pBN, bool set) {

		ERR_STATUS err;
		int ctxSize;

		err = ippsBigNumGetSize(size, &ctxSize);						// Calculate size
		if (err != ippStsNoErr)
			return err;

		pBN = (IppsBigNumState*)(new (std::nothrow) Ipp8u[ctxSize]);	// Allocate the Big Number context
		if (pBN == NULL)
			return ippStsMemAllocErr;

		err = ippsBigNumInit(size, pBN);								// Init
		if (err != ippStsNoErr)
			return err;

		if (set) { // If a value needed
			Ipp32u* pBuffer = new Ipp32u[size];
			err = ippsSet_BN(IppsBigNumPOS, size, rand32(pBuffer, size), pBN); // Generate
			delete[] pBuffer;
		}

		return err;
	}

	inline void delete_BigNumState(IppsBigNumState* pBN) {
		 delete[](Ipp8u*)pBN;
	 }

	inline void sqrt_BigNumState(IppsBigNumState* pBN, IppsBigNumState *pR) {
		
		BigNumber x = pBN, y = 1;
		
		while (x - y > 5) {
			x = (x + y) / 2;
			y = pBN / x;
		}

		pR = x;
	}

	inline Ipp32u* rand32(Ipp32u* pX, int size) {
		 std::srand(std::time(nullptr)); // Seed with current time
		 for (int n = 0; n < size; n++)
			 pX[n] = (rand() << 16) + rand();
		 return pX;
	}

	inline Ipp8u* rand8(Ipp8u* pX, int size) {
		std::srand(std::time(nullptr)); // Seed with current time
		for (int n = 0; n < size; n++)
			pX[n] = rand();
		return pX;
	}

	inline size_t getFileSize(FILE *&pFile) {
		fseek(pFile, 0, SEEK_END);
		size_t size = ftell(pFile);
		fseek(pFile, 0, SEEK_SET);
		return size;
	}

}
