// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utils.h"

#include <cstdlib>
#include <ctime>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <thread>
#include <vector>

std::string palscash::log::get_timestamp(std::string const & logging_level) {

	std::stringstream ss;

	auto this_id = std::this_thread::get_id();

	auto t = std::time(nullptr);

	auto now = std::localtime(&t); //

	ss << (now->tm_year + 1900) << '-' //
			<< std::setw(2) << std::setfill('0') << (now->tm_mon + 1) << '-' //
			<< std::setw(2) << std::setfill('0') << now->tm_mday << ' ' //
			<< std::setw(2) << std::setfill('0') << now->tm_hour << ':' //
			<< std::setw(2) << std::setfill('0') << now->tm_min << ':' //
			<< std::setw(2) << std::setfill('0') << now->tm_sec //
			<< ' ' << logging_level //
			<< " [" << this_id << "] ";

	return ss.str();
	
}

void palscash::log::info(const std::string& msg) {
	std::cout << get_timestamp("INFO") << msg << std::endl;
}

void palscash::log::warn(const std::string& msg) {
	std::cout << get_timestamp("WARN") << msg << std::endl;
}

void palscash::log::error(const std::string& msg) {
	std::cerr << get_timestamp("ERROR") << msg << std::endl;
}

std::string palscash::network::get_random_network_host() {

	std::vector<std::string> list;

	list.push_back("coinmonitor.services");
	list.push_back("blockchain-monitor.live");
	list.push_back("crypto-networks.network");
	list.push_back("fastcoins.online");
	list.push_back("realtimepayments.me");
	list.push_back("cryptonews.solutions");
	list.push_back("palscash.live");
	list.push_back("palscash.network");
	list.push_back("palscash.online");
	list.push_back("palscash.services");

	auto randIt = list.begin();
	std::advance(randIt, std::rand() % list.size());

	auto host = "https://" + (*randIt);

	return host;

}
