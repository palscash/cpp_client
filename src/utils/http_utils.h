// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTILS_HTTP_UTILS_H_
#define UTILS_HTTP_UTILS_H_

#include <curl/curl.h>

#include <string>

namespace palscash {

	namespace http {

		enum class HttpMethod {
			POST, GET
		};

		class operation final {
			public:
				palscash::http::HttpMethod method = palscash::http::HttpMethod::GET;
				std::string query;
				std::string body;
				std::string proxy;
				bool insecure = false;
				bool verbose = false;
				int timeout = 10000;
				std::string user_agent;
				std::string version;
		};
	}

	namespace http {

		size_t data_write(void* buf, size_t size, size_t nmemb, void* userp);

		class httpresponse final {

			public:

				bool error = false;

				std::string data;

				std::string contentType;

				unsigned int length = -1;

		};

		class httpclient final {

			public:

				httpclient();

				~httpclient();

				void send(const palscash::http::operation& op);

			private:

				CURL* curl = nullptr;

		};

	}
}

#endif /* UTILS_HTTP_UTILS_H_ */
