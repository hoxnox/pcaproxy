/**@author $username$ <$usermail$>
 * @date $date$*/

#include "Config.hpp"
#include "HttpReqInfo.hpp"
#include "Logger.hpp"
#include <utils/Utils.hpp>
#include <gettext.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace pcaproxy {

std::hash<std::string> HttpReqInfo::hashFn;

HttpReqInfo::HttpReqInfo(const char* data, size_t dataln)
	: url_hash_(0)
{
	ssize_t i = 0;
	for (; std::isalpha(data[i]) && i < 7 && i < dataln; ++i)
		method_ += data[i];
	if (method_ != "OPTIONS"
	 && method_ != "GET"
	 && method_ != "HEAD"
	 && method_ != "POST"
	 && method_ != "PUT"
	 && method_ != "DELETE"
	 && method_ != "TRACE"
	 && method_ != "CONNECT")
	{
		method_ = "";
		return;
	}

	ssize_t left = i;
	while (data[i] != '\n' && data[i-1] != '\r' && i < dataln)
		++i;
	const std::string http_1 = " HTTP/1.1\r\n";
	if (i - left < http_1.length())
	{
		method_ = "";
		return;
	}
	ssize_t right = i - http_1.length();
	if (std::string(data + right + 1, data + i + 1) != http_1)
	{
		method_ = "";
		return;
	}

	url_.assign(data + left, data + right);
	trim(url_);
	url_hash_ = hashFn(url_);
	Config::Ptr cfg = Config::GetInstance();
	std::stringstream ss;
	ss << cfg->ParseDir() << "/";
	ss << std::setw(16) << std::setfill('0') << std::hex << url_hash_;
	fname_ = ss.str();
	/*
	VLOG << _("HttpReqInfo: fetched request.")
	     << _(" Method: ") << req.method_
	     << _(" URL: ") << url
	     << _(" URL hash: ") << req.url_hash_;
	*/
}

} // namespace

