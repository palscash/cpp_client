// Copyright (c) 2016-2018 The ZDP developers
// Copyright (c) 2018 PalsCash team
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>

#include "args.hpp"
#include "json.hpp"
#include "utils/base58.h"
#include "utils/crypto_utils.h"
#include "utils/http_utils.h"
#include "utils/key_pair.h"
#include "utils/open_ssl_helper.h"
#include "utils/utils.h"

std::string VERSION = "2.0.2";

constexpr auto TIMEOUT = 10000;
constexpr auto USER_AGENT = "palscash/cpp-cli/";

void generate_account(palscash::key_pair& kp, bool verbose) {

	using nlohmann::json;

	const auto default_curve = "secp256k1";

	json j = { { "accountUuid", kp.to_account_uuid() }, { "curve", default_curve }, { "privateKey", kp.get_private_key() }, { "publicKey", kp.get_public_key() }, { "type", "account-details" } };

	if (verbose) {
		std::cout << palscash::log::get_timestamp(LOGGING_INFO);
	}

	std::cout << j.dump(4) << std::endl;

}

int main(int argc, const char **argv) {

	auto st = std::chrono::system_clock::now();

	using nlohmann::json;

	std::srand(std::time(nullptr));

	palscash::open_ssl_helper ossl;

	args::Group arguments("Arguments");

	args::HelpFlag help(arguments, "help", "Print this help", { "help", "h" });
	args::Flag verboseFlag(arguments, "verbose", "Display additional information (verbose output)", { "verbose" });
	args::ValueFlag<std::string> proxyFlag(arguments, "proxy", "Specify proxy host and port (i.e. https://proxy.corp:8080)", { "proxy" });
	args::Flag insecureFlag(arguments, "insecure", "This option explicitly allows curl to perform \"insecure\" SSL connections and transfers", { "insecure" });

	args::ArgumentParser p("PalsCash Client (palscash.org) - Distributed under the MIT software license");

	args::Group commands(p, "Commands");

	palscash::http::operation operation;
	operation.timeout = TIMEOUT;
	operation.user_agent = USER_AGENT;
	operation.version = VERSION;

	palscash::http::httpclient http_client;

	args::Command version(commands, "version", "Output version number", [&](args::Subparser &parser)
	{

		parser.Parse();

		std::cout << VERSION << std::endl;

	});

	args::Command fee(commands, "fee", "Get the current network fee", [&](args::Subparser &parser)
	{

		parser.Parse();

		operation.query = "/api/fee";

		http_client.send(operation);

	});

	args::Command ping(commands, "ping", "Ping the network", [&](args::Subparser &parser)
	{

		parser.Parse();

		operation.query = "/api/ping";
		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		http_client.send(operation);

	});

	args::Command newAccount(commands, "newaccount", "Create new account", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> langArg(parser, "LANGUAGE", "Mnemonics language", {"lang"}, "english");
		args::ValueFlag<std::string> curveArg(parser, "CURVE", "Elliptic curve algorithm to use", {"curve"}, "secp256r1");
		args::Flag offlineArg(parser, "OFFLINE", "Generate offline (using secp256k1 curve)", {"offline"});

		parser.Parse();

		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		if (offlineArg.Get()) {

			palscash::key_pair kp;
			generate_account(kp, operation.verbose);

		} else {

			json j = {
				{	"curve", curveArg.Get()},
				{	"language", langArg.Get()},
			};

			operation.query = "/api/ping";
			operation.method = palscash::http::HttpMethod::POST;
			operation.body = j;

			http_client.send(operation);

		}

	});

	args::Command address(commands, "address", "Generate address from a private key", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> keyArg(parser, "PRIVATE_KEY", "Private key", {"key"}, args::Options::Required);

		parser.Parse();

		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		palscash::key_pair kp(keyArg.Get());

		generate_account(kp, operation.verbose);

	});

	args::Command balance(commands, "balance", "Get account's balance", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> addressArg(parser, "ADDRESS", "Account address", {"address"}, args::Options::Required);

		parser.Parse();

		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		operation.query = "/api/account/balance/"+addressArg.Get();

		http_client.send(operation);

	});

	args::Command account(commands, "account", "Get account's details", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> addressArg(parser, "ADDRESS", "Account address", {"address"}, args::Options::Required);

		parser.Parse();

		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		operation.query = "/api/account/get/"+addressArg.Get();

		http_client.send(operation);

	});

	args::Command count(commands, "count", "Count account's transactions", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> addressArg(parser, "ADDRESS", "Account address", {"address"}, args::Options::Required);

		parser.Parse();

		operation.query = "/api/tx/count/"+addressArg.Get();
		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		http_client.send(operation);

	});

	args::Command listTransactionsFrom(commands, "listfrom", "List FROM account's transactions", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> addressArg(parser, "ADDRESS", "Account address", {"address"}, args::Options::Required);

		parser.Parse();

		operation.query = "/api/list/tx/from/"+addressArg.Get();
		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		http_client.send(operation);

	});

	args::Command listTransactionsTo(commands, "listto", "List TO account's transactions", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> addressArg(parser, "ADDRESS", "Account address", {"address"}, args::Options::Required);

		parser.Parse();

		operation.query = "/api/list/tx/to/"+addressArg.Get();
		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		http_client.send(operation);

	});

	args::Command tx(commands, "tx", "Get transaction details", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> uuidArg(parser, "UUID", "Transaction UUID", {"uuid"}, args::Options::Required);

		parser.Parse();

		operation.query = "/api/tx/"+uuidArg.Get();
		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		http_client.send(operation);

	});

	args::Command transfer(commands, "transfer", "Transfer coins to another account", [&](args::Subparser &parser)
	{

		args::ValueFlag<std::string> fromArg(parser, "FROM", "From address", {"from"}, args::Options::Required);
		args::ValueFlag<std::string> toArg(parser, "TO", "To address", {"to"}, args::Options::Required);
		args::ValueFlag<std::string> amountArg(parser, "AMOUNT", "Amount to transfer", {"amount"}, args::Options::Required);
		args::ValueFlag<std::string> memoArg(parser, "MEMO", "Memo", {"memo"}, args::Options::Required);
		args::ValueFlag<std::string> privateKeyArg(parser, "PRIVATE KEY", "Sender's private key", {"key"}, args::Options::Required);
		args::ValueFlag<std::string> requestUuidArg(parser, "REQUEST_UUID", "Request UUID", {"request_uuid"});

		parser.Parse();

		operation.insecure = insecureFlag.Get();
		operation.verbose = verboseFlag.Get();
		operation.proxy = proxyFlag.Get();

		auto from = args::get(fromArg);
		auto to = args::get(toArg);
		auto amount = args::get(amountArg);
		auto memo = args::get(memoArg);
		auto key = args::get(privateKeyArg);
		auto request_uuid = args::get(requestUuidArg);

		using namespace std::chrono;

		auto ms = duration_cast< milliseconds >(
				system_clock::now().time_since_epoch()
		);

		auto time = std::to_string ( ms.count() );

		// Sign transfer
			std::string transfer_signature_body = from + amount + to + request_uuid + time;

			auto sig = palscash::crypto::sign(key, transfer_signature_body);

			auto signature58 = palscash::base58::encode_base(sig);

			if (operation.verbose) {
				palscash::log::info("Transfer signature: " + transfer_signature_body);
				palscash::log::info("Transfer signature (Base58): " + signature58);
			}

			palscash::key_pair kp(key);

			json j = {
				{	"from", from},
				{	"to", to},
				{	"amount", amount},
				{	"memo", memo},
				{	"requestUuid", request_uuid},
				{	"signature", signature58},
				{	"time", time},
				{	"publicKey", kp.get_public_key()}
			};

			if (operation.verbose) {
				palscash::log::info("Request: " + j.dump(4));
			}

			operation.method = palscash::http::HttpMethod::POST;
			operation.body = j.dump();
			operation.query = "/api/transfer";

			http_client.send(operation);

		});

	args::GlobalOptions globals(p, arguments);

	try {
		p.ParseCLI(argc, argv);
	} catch (args::Help) {
		std::cout << p;
	} catch (args::Error& e) {
		std::cerr << e.what() << std::endl << p;
		return EXIT_FAILURE;
	}

	auto et = std::chrono::system_clock::now();

	if (operation.verbose) {
		palscash::log::info("Time taken: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(et - st).count()) + " ms.");
	}

	return EXIT_SUCCESS;
}
