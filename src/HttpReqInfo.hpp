/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __HTTP_REQ_INFO_HPP__
#define __HTTP_REQ_INFO_HPP__

#include <functional>
#include <string>

namespace pcaproxy {

class HttpReqInfo
{
public:
	HttpReqInfo(const char* data, size_t dataln);
	std::string Method() const { return method_; };
	std::string Url() const { return url_; }
	size_t      UrlHash() const { return url_hash_; };
	std::string FName() const { return fname_; }
private:
	std::string method_;
	size_t      url_hash_;
	std::string url_;
	std::string fname_;
	static std::hash<std::string> hashFn;
};

} // namespace

#endif // __HTTP_REQ_INFO_HPP__

