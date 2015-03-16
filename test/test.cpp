/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18
 *
 * @brief pcaproxy test launcher.*/

// Google Testing Framework
#include <gtest/gtest.h>

// test cases

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}


