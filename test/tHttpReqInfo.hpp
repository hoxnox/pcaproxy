/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150318 11:59:38*/

#include <HttpReqInfo.hpp>
#include <vector>

using namespace pcaproxy;

class TestHttpReqInfo : public ::testing::Test
{
protected:
	TestHttpReqInfo()
	{
	}
	void SetUp()
	{
		cfg = Config::GetInstance();
	}
	Config::Ptr cfg;
};

TEST_F(TestHttpReqInfo, ctor)
{

	std::string s01 =
		"GET /pic/cat/24.gif HTTP/1.1\r\n"
		"Host: kinozal.tv\r\n"
		"Connection: keep-alive\r\n"
		"Accept: image/webp,*/*;q=0.8\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n"
		"Referer: http://kinozal.tv/\r\n"
		"Accept-Encoding: gzip,deflate,sdch\r\n"
		"Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
		"Cookie: uid=4027998; pass=adb0d0c67ababa4f4845476f70d3f369\r\n"
		"DNT: 1\r\n";

	HttpReqInfo r01(s01.c_str(), s01.length());
	EXPECT_EQ("GET", r01.Method());
	EXPECT_EQ("http://kinozal.tv/pic/cat/24.gif", r01.Url());
	EXPECT_EQ("4ecb6c5abc05f59b", r01.UrlHash());
	EXPECT_EQ(cfg->ParseDir() + "/" + r01.UrlHash() + ".dat", r01.FName());
	EXPECT_EQ("http://kinozal.tv/", r01.Referer());

	std::string s02 = 
		"GET /_ugc/images//SurvivingJack_shownav_dropdown_132x72.jpg HTTP/1.1\r\n"
		"Host: www.fox.com\r\n"
		"Connection: keep-alive\r\n"
		"Accept: image/webp,*/*;q=0.8\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36\r\n"
		"Accept-Encoding: gzip,deflate,sdch\r\n"
		"Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4,fr;q=0.2,it;q=0.2\r\n"
		"Cookie: mbox=check#true#1399032868|session#1399032807188-668675#1399034668\r\n";

	HttpReqInfo r02(s02.c_str(), s02.length());
	EXPECT_EQ("GET", r02.Method());
	EXPECT_EQ("http://www.fox.com/_ugc/images//SurvivingJack_shownav_dropdown_132x72.jpg", r02.Url());
	EXPECT_EQ("7551d2134fe1f2be", r02.UrlHash());
	EXPECT_EQ(cfg->ParseDir() + "/" + r02.UrlHash() + ".dat", r02.FName());
	EXPECT_TRUE(r02.Referer().empty());


	std::string s03 = 
		"GET / HTTP/1.1\r\n"
		"Host: kinozal.tv\r\n"
		"Connection: keep-alive\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n"
		"Accept-Encoding: gzip,deflate,sdch\r\n"
		"Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
		"Cookie: uid=4027998; pass=adb0d0c67ababa4f4845476f70d3f369\r\n"
		"DNT: 1\r\n";

	HttpReqInfo r03(s03.c_str(), s03.length());
	EXPECT_EQ("GET", r03.Method());
	EXPECT_EQ("http://kinozal.tv/", r03.Url());
	EXPECT_EQ("3579b104b41c2632", r03.UrlHash());
	EXPECT_EQ(cfg->ParseDir() + "/" + r03.UrlHash() + ".dat", r03.FName());
	EXPECT_TRUE(r03.Referer().empty());
}


