// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTILS_UTILS_H_
#define UTILS_UTILS_H_

#include <string>

#define LOGGING_INFO "INFO"
#define LOGGING_WARN "WARN"
#define LOGGING_ERROR "ERROR"

namespace palscash {
	namespace log {

		void info(const std::string& msg);
		void warn(const std::string& msg);
		void error(const std::string& msg);
		std::string get_timestamp(const std::string& logging_level);
	}

	namespace network {

		std::string get_random_network_host();

	}
}

#endif /* UTILS_UTILS_H_ */
