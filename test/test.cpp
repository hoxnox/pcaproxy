/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18
 *
 * @brief pcaproxy test launcher.*/

// Google Testing Framework
#include <gtest/gtest.h>
#include <Config.hpp>
#include <utils/Utils.hpp>
#include <vector>
#include <string>

// test cases
#include "tHttpReqInfo.hpp"

void setupConfig(Config::Ptr cfg, std::string argstring)
{
	std::vector<std::string> args_v;
	split(argstring, std::back_inserter(args_v), " ", false);
	char** args = new char*[args_v.size()];
	for (size_t i =0; i < args_v.size(); ++i)
	{
		args[i] = new char[args_v[i].length()];
		std::copy(args_v[i].begin(), args_v[i].end(), args[i]);
	}
	cfg->ParseArgs(args_v.size(), args);
	for (size_t i =0; i != args_v.size(); ++i)
		delete [] args[i];
	delete [] args;
}

int main(int argc, char *argv[])
{
	setupConfig(Config::GetInstance(), "-p /tmp/__test__.pcaparse");
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}


