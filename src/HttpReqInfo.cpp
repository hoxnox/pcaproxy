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

void
HttpReqInfo::parseReqStr(const std::string& line)
{
	ssize_t i = 0;
	for (; std::isalpha(line[i]) && i < 7 && i < line.length(); ++i)
		method_ += line[i];
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
	ssize_t right = line.find(" HTTP/1.1");
	if (right == std::string::npos || right <= left)
	{
		method_ = "";
		return;
	}
	
	url_ = line.substr(left, right - left);
	trim(url_);
	update();
	VLOG << _("HttpReqInfo: fetched request.")
	     << _(" Method: \"") << method_ << "\""
	     << _(" URL: \"") << url_ << "\""
	     << _(" URL hash: ") << url_hash_;
}

void
HttpReqInfo::update()
{
	size_t url_hash = hashFn(url_);
	Config::Ptr cfg = Config::GetInstance();
	std::stringstream ss;
	ss << std::setw(16) << std::setfill('0') << std::hex << url_hash;
	url_hash_ = ss.str();
	fname_ = cfg->ParseDir() + "/" + url_hash_;
}

void
HttpReqInfo::parseHdrStr(const std::string& line)
{
	std::smatch sm;
	if (regex_match(line, sm, rgx_host))
	{
		url_ = "http://" + sm[1].str() + url_;
		VLOG << _("HttpReqInfo: host found, URL updated.")
		     << _(" Host: \"") << sm[1].str() << "\""
		     << _(" URL: \"") << url_ << "\"";
		update();
	}
}

HttpReqInfo::HttpReqInfo(const char* data, size_t dataln)
	: rgx_host("^host:\\s*(.*)", std::regex::icase)
{
	for(ssize_t pos = 3; pos < dataln; ++pos)
	{
		if (data[pos - 3] == '\r' && data[pos - 2] == '\n'
		 && data[pos - 1] == '\r' && data[pos]     == '\n')
		{
			dataln = pos - 3;
			break;
		}
	}
	std::vector<std::string> lines;
	split(std::string(data, data + dataln), std::back_inserter(lines), "\r\n");
	if (lines.empty())
		return;
	parseReqStr(lines[0]);
	if (method_ == "")
		return;
	if (url_.substr(0, 7) != "http://")
	{
		bool prev_empty = false;
		for(size_t i = 1; i < lines.size(); ++i)
		{
			if (lines[i].empty())
			{
				if (prev_empty)
					break;
				prev_empty = true;
				continue;
			}
			prev_empty = false;
			parseHdrStr(lines[i]);
		}
	}
}

} // namespace

