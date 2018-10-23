// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "http_utils.h"

#include <curl/easy.h>
#include <iostream>
#include <sstream>

#include "../json.hpp"
#include "utils.h"

namespace palscash {

	namespace http {

		size_t data_write(void* buf, size_t size, size_t nmemb, void* userp) {
			if (userp) {
				std::ostream& os = *static_cast<std::ostream*>(userp);
				std::streamsize len = size * nmemb;
				if (os.write(static_cast<char*>(buf), len))
					return len;
			}

			return 0;
		}

		httpclient::httpclient() {
			this->curl = curl_easy_init();
		}

		httpclient::~httpclient() {
			if (curl != nullptr) {
				curl_easy_cleanup(curl);
			}
		}

		void httpclient::send(const palscash::http::operation& op) {

			using nlohmann::json;

			auto host = palscash::network::get_random_network_host();

			auto url = host + op.query;

			if (op.verbose) {

				std::cout << palscash::log::get_timestamp(LOGGING_INFO) << "Network host: " << host << std::endl;

				if (op.method == palscash::http::HttpMethod::GET) {
					palscash::log::info("HTTP Get [" + url + "]");
				} else {
					palscash::log::info("HTTP Post [" + url + "] of " + op.body);
				}

				palscash::log::info("User-Agent: " + op.user_agent + op.version);
				palscash::log::info("Connection timeout (ms): " + std::to_string(op.timeout));

			}

			std::ostringstream stream;

			if (false == op.proxy.empty()) {
				curl_easy_setopt(curl, CURLOPT_PROXY, op.proxy.c_str());
			}

			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &data_write);
			curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
			curl_easy_setopt(curl, CURLOPT_FILE, &stream);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, op.timeout);
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
			curl_easy_setopt(curl, CURLOPT_USERAGENT, op.user_agent.c_str());

			if (op.method == palscash::http::HttpMethod::POST) {
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, op.body.c_str());
			}

			if (op.insecure) {
				curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

				if (op.verbose) {

					palscash::log::warn("Turning off SSL certificates verification (insecure)");
				}
			}

			// Set up headers
			struct curl_slist *headers = nullptr;
			headers = curl_slist_append(headers, "Accept: application/json");
			headers = curl_slist_append(headers, "Content-Type: application/json");
			headers = curl_slist_append(headers, "charsets: utf-8");
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

			httpresponse response;

			CURLcode res = curl_easy_perform(curl);

			if (res != CURLE_OK) {

				if (op.verbose) {
					std::cout << palscash::log::get_timestamp(LOGGING_INFO);
				}

				std::cerr << "ERROR: Cannot connect to the network: \"" << url << "\" (error code: " << std::to_string(res) << ')' << std::endl;

				response.error = true;

			} else {

				if (CURLE_OK == res) {

					char *ct = nullptr;

					/* ask for the content-type */
					res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

					if ((CURLE_OK == res) && ct) {
						response.contentType = std::string(ct);
					}

					response.data = stream.str();
					response.length = response.data.size();

					if (op.verbose) {
						palscash::log::info("Response type: " + response.contentType);
						palscash::log::info("Response length: " + std::to_string(response.length));
					}

				}
			}

			if (!response.error) {

				auto json = json::parse(response.data);

				if (op.verbose) {
					std::cout << palscash::log::get_timestamp(LOGGING_INFO);
				}

				std::cout << json.dump(4) << std::endl;
			}

		}

	}
}
