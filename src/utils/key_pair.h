// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTILS_KEY_PAIR_H_
#define UTILS_KEY_PAIR_H_

#include <string>

namespace palscash {
	
	class key_pair final {

		private:

			std::string private_key;
			std::string public_key;

			std::vector<unsigned char> pub_byte_array;
			std::vector<unsigned char> priv_byte_array;

		public:

			/**
			 * Create a new key pair
			 */
			key_pair();

			/*
			 * Create from an existing private key
			 */
			key_pair(std::string priv_key);

			~key_pair();

			std::string const & get_private_key() const;

			std::string const & get_public_key() const;

			std::vector<unsigned char> const & get_priv_byte_array() const;

			std::vector<unsigned char> const & get_pub_byte_array() const;

			std::string to_account_uuid();

	};

} /* namespace palscash */

#endif /* UTILS_KEY_PAIR_H_ */
