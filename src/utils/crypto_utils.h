// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTILS_CRYPTO_UTILS_H_
#define UTILS_CRYPTO_UTILS_H_

#include <openssl/ossl_typ.h>
#include <openssl/ec.h>

#include <string>
#include <vector>

namespace palscash {
	namespace crypto {

		std::vector<unsigned char> random(const unsigned int length);

		std::string sha256Hex(std::string& value);
		std::string sha256Hex(std::vector<unsigned char>& value);
		std::vector<unsigned char> sha256(std::vector<unsigned char>& value);
		std::vector<unsigned char> sha256(std::string& str);

		std::vector<unsigned char> ripemd160(std::vector<unsigned char>& value);

		EC_KEY *ec_new_keypair(std::vector<unsigned char>& byte_array);
		EC_KEY *ec_new_pubkey(std::vector<unsigned char>& pub_key);

		std::string get_public_key(std::string& private_key);

		std::vector<unsigned char> sign(std::string& private_key_58, std::string& msg);

		std::vector<unsigned char> hash_public_key(std::vector<unsigned char>& value);

		std::vector<unsigned char> hash_transaction_data(std::string& value);

		unsigned int checksum(std::vector<unsigned char>& value);
	}
}

#endif /* UTILS_CRYPTO_UTILS_H_ */
