// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "open_ssl_helper.h"

namespace palscash {
		
		open_ssl_helper::open_ssl_helper() {
			
			#ifdef __linux__

				// Load the human readable error strings for libcrypto
				 ERR_load_crypto_strings();

				 // Load all digest and cipher algorithms
				 OpenSSL_add_all_algorithms();

				 // Load config file, and other important initialisation
				 OPENSSL_config(NULL);
			#endif

		}
		
		open_ssl_helper::~open_ssl_helper() {

			EVP_cleanup();

			CRYPTO_cleanup_all_ex_data();

			ERR_free_strings();

		}
	
} /* namespace palscash */
