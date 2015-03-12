/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __HTTP_REQ_INFO_HPP__
#define __HTTP_REQ_INFO_HPP__

#include <functional>
#include <string>
#include <regex>

namespace pcaproxy {

class HttpReqInfo
{
public:
	HttpReqInfo(const char* data, size_t dataln);
	std::string Method() const { return method_; };
	std::string Url() const { return url_; }
	std::string UrlHash() const { return url_hash_; };
	std::string FName() const { return fname_; }
private:
	void parseReqStr(const std::string& line);
	void parseHdrStr(const std::string& line);
	void update();
	std::string method_;
	std::regex  rgx_host;
	std::string url_hash_;
	std::string url_;
	std::string fname_;
	static std::hash<std::string> hashFn;
};

} // namespace

#endif // __HTTP_REQ_INFO_HPP__

