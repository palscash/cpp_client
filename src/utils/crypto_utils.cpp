// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto_utils.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ripemd.h>

#include "base58.h"

EC_KEY *palscash::crypto::ec_new_keypair(std::vector<unsigned char>& priv_bytes) {

	EC_KEY *key = nullptr;
	BIGNUM *priv = nullptr;
	BN_CTX *ctx = nullptr;
	const EC_GROUP *group = nullptr;
	EC_POINT *pub = nullptr;

	key = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (!key) {
		std::cerr << "Can't generate curve secp256k1\n";
		std::abort();
	}

	priv = BN_new();
	BN_bin2bn(priv_bytes.data(), 32, priv);
	EC_KEY_set_private_key(key, priv);

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	group = EC_KEY_get0_group(key);
	pub = EC_POINT_new(group);
	EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
	EC_KEY_set_public_key(key, pub);

	EC_POINT_free(pub);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_clear_free(priv);

	return key;
}

EC_KEY *palscash::crypto::ec_new_pubkey(std::vector<unsigned char>& pub_key) {

	EC_KEY *key = nullptr;
	const uint8_t *pub_bytes_copy = nullptr;

	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	pub_bytes_copy = pub_key.data();
	o2i_ECPublicKey(&key, &pub_bytes_copy, pub_key.size());

	return key;
}

std::string palscash::crypto::get_public_key(std::string& priv_key) {

	auto byte_array = palscash::base58::decode_base(priv_key);

	auto key = palscash::crypto::ec_new_keypair(byte_array);

	// Public key in Base58

	auto pub_bn = BN_new();

	EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), point_conversion_form_t::POINT_CONVERSION_COMPRESSED, pub_bn, nullptr);

	std::vector<unsigned char> pub_byte_array(BN_num_bytes(pub_bn));

	BN_bn2bin(pub_bn, pub_byte_array.data());

	auto pub_base58 = palscash::base58::encode_base(pub_byte_array);

	return std::string(pub_base58);

}

std::vector<unsigned char> palscash::crypto::sha256(std::string& str) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

	std::vector<unsigned char> data(hash, hash + SHA256_DIGEST_LENGTH);

	return data;

}

std::string palscash::crypto::sha256Hex(std::string& str) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
	}
	return ss.str();

}

std::string palscash::crypto::sha256Hex(std::vector<unsigned char>& unhashed) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, unhashed.data(), unhashed.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
	}
	return ss.str();

}

std::vector<unsigned char> palscash::crypto::random(const unsigned int length) {

	std::vector<unsigned char> buffer(length);

	RAND_bytes(buffer.data(), length);

	return buffer;

}

std::vector<unsigned char> palscash::crypto::sign(std::string& private_key_58, std::string& message) {

	auto priv_bytes = palscash::base58::decode_base(private_key_58);

	auto digest = palscash::crypto::sha256(message);

	auto key = palscash::crypto::ec_new_keypair(priv_bytes);

	auto signature = ECDSA_do_sign(digest.data(), digest.size(), key);

	auto der_len = ECDSA_size(key);
	auto der = (uint8_t*) calloc(der_len, sizeof(uint8_t));
	auto der_copy = der;
	auto signature_length = i2d_ECDSA_SIG(signature, &der_copy);

	std::vector<unsigned char> s(der, der + signature_length);

	return s;

}

std::vector<unsigned char> palscash::crypto::sha256(std::vector<unsigned char>& unhashed) {

	std::vector<unsigned char> output(SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, unhashed.data(), unhashed.size());
	SHA256_Final(output.data(), &ctx);

	return output;

}

std::vector<unsigned char> palscash::crypto::ripemd160(std::vector<unsigned char>& unhashed) {

	std::vector<unsigned char> output(RIPEMD160_DIGEST_LENGTH);

	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, unhashed.data(), unhashed.size());
	RIPEMD160_Final(output.data(), &ctx);

	return output;
}

std::vector<unsigned char> palscash::crypto::hash_public_key(std::vector<unsigned char>& value) {

	auto hashed = palscash::crypto::sha256(value);

	hashed = palscash::crypto::sha256(hashed);

	hashed = palscash::crypto::ripemd160(hashed);

	return hashed;
}

std::vector<unsigned char> palscash::crypto::hash_transaction_data(std::string& value) {

	unsigned char* arr = (unsigned char*) value.c_str();

	std::vector<unsigned char> data(arr, arr + value.size());

	auto hashed = palscash::crypto::sha256(data);

	hashed = palscash::crypto::ripemd160(hashed);

	return hashed;

}

unsigned int palscash::crypto::checksum(std::vector<unsigned char>& value) {

	constexpr auto CRC_POLYNOM = 0x9c;
	constexpr auto CRC_PRESET = 0xFF;

	unsigned int crc = CRC_PRESET;

	for (int i = 0; i < value.size(); i++) {
		crc ^= value[i];
//		std::cout << std::to_string(i) << " " << std::to_string(crc) << " " << std::to_string(value[i]) << std::endl;

		for (int j = 0; j < 8; j++) {
			if (crc & 0x01) {
				crc = (crc >> 1) ^ CRC_POLYNOM;
			} else {
				crc = (crc >> 1);
			}
		}
	}

	return crc;
}

