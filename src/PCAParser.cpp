/**@author $username$ <$usermail$>
 * @date $date$ */


#include <nids.h>
#include "PCAParser.hpp"
#include "Config.hpp"

#include <Logger.hpp>
#include <Endians.hpp>
#include <utils/NxSocket.h>
#include <utils/MkDir.h>
#include <gettext.h>

#include <cstring>
#include <string>
#include <sstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <memory>
#include <locale>
#include <functional>
#include <algorithm>

namespace pcaproxy {

PCAParser::Ptr PCAParser::instance_(NULL);

/**@brief Create directories (recursive)
 * @note will be created directories before
 * the last occurring of '/'. For example: "test/my/dirs" will create
 * "test" and "my", but "test/my/dirs/" creates all of them.*/
inline bool check_create_dir(std::string path)
{
	size_t tmp = path.find_last_of('/');
	if(tmp == std::string::npos)
		return true;
	path = path.substr(0, tmp);

	if (mkpath(path.c_str(),
			S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)
	{
		ELOG << _("Error creating output directory") << " \""
			<< path << "\"";
		return false;
	}
	return true;
}

inline char
hex2char(unsigned char n)
{
	if(0 <= n && n <= 9)
		return n + 48;
	if(0xA <= n && n <= 0xF)
		return n - 0xA + 65;
	return '?';
}

inline std::string
byte2str(const char * bytes, const size_t bytesz)
{
	std::string result;
	if (bytes == NULL || bytesz == 0)
		return result;
	for(size_t i = 0; i < bytesz; ++i)
	{
		result += hex2char((((unsigned char)bytes[i])/0x10)%0x10);
		result += hex2char(((unsigned char)bytes[i])%0x10);
	}
	return result;
}

inline std::string
byte2str(std::vector<char>& bytes)
{
	return byte2str((const char*)&bytes[0], bytes.size());
}

void
PCAParser::nidsLogger(int type, int err, struct ip *iph, void *data)
{
	if (type == 2 && err == 8) // WTF?!
		return;
	ILOG << "NIDS error: "
	     << _(" Message type: ") << type
	     << _(" Error code: ") << err;
}

inline std::string
inet_ntos(uint32_t num)
{
	char buf[50];
	memset(buf, 0, sizeof(buf));
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = num;
	if (inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf) - 1) == NULL)
	{
		ELOG << _("PCAParser: error converting IPv4 to string.")
		     << _(" Message: ") << strerror(errno);
		return "";
	}
	return std::string(buf);
}

inline std::string
addr_info(const struct tuple4& addr, std::string delim = "vs")
{
	std::stringstream ss;
	ss << inet_ntos(addr.saddr) << ":" << addr.source;
	ss << " " << delim << " ";
	ss << inet_ntos(addr.daddr) << ":" << addr.dest;
	return ss.str();
}

static inline std::string&
ltrim(std::string &s)
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

static inline std::string&
rtrim(std::string &s)
{
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

static inline std::string&
trim(std::string &s)
{
	return ltrim(rtrim(s));
}

std::hash<std::string> HttpReqInfo::hashFn;

HttpReqInfo
HttpReqInfo::fromRequest(const char* data, size_t dataln)
{
	ssize_t i = 0;
	HttpReqInfo req;
	for (; std::isalpha(data[i]) && i < 7 && i < dataln; ++i)
		req.method_ += data[i];
	if (req.method_ != "OPTIONS"
	 && req.method_ != "GET"
	 && req.method_ != "HEAD"
	 && req.method_ != "POST"
	 && req.method_ != "PUT"
	 && req.method_ != "DELETE"
	 && req.method_ != "TRACE"
	 && req.method_ != "CONNECT")
	{
		return HttpReqInfo();
	}

	ssize_t left = i;
	while (data[i] != '\n' && data[i-1] != '\r' && i < dataln)
		++i;
	const std::string http_1 = " HTTP/1.1\r\n";
	if (i - left < http_1.length())
		return HttpReqInfo();
	ssize_t right = i - http_1.length();
	if (std::string(data + right + 1, data + i + 1) != http_1)
		return HttpReqInfo();

	std::string url(data + left, data + right);
	trim(url);
	req.url_hash_ = hashFn(url);
	VLOG << _("HttpReqInfo: fetched request.")
	     << _(" Method: ") << req.method_
	     << _(" URL: ") << url
	     << _(" URL hash: ") << req.url_hash_;
	return req;
}

void
PCAParser::tcpCallback(struct tcp_stream *stream, void** params)
{
	if (stream->addr.dest != 80 && stream->addr.source != 80)
	{
		VLOG << _("PCAParser: skipping traffic: ") << addr_info(stream->addr);
		return;
	}

	std::ofstream* ofile = reinterpret_cast<std::ofstream*>(stream->user);
	if (stream->nids_state == NIDS_JUST_EST)
	{
		stream->client.collect++;
		stream->server.collect++;
		stream->user = NULL;
		VLOG << _("PCAParser: TCP ESTABLISHED: ") << addr_info(stream->addr);
		return;
	}
	else if (stream->nids_state == NIDS_DATA)
	{
		if (stream->client.count_new > 0 && ofile != NULL)
		{
			if (ofile->good())
			{
				std::ostreambuf_iterator<char> writer(ofile->rdbuf());
				char* data = stream->client.data;
				std::copy(data, data + stream->client.count_new, writer);
			}
			else
			{
				delete ofile;
				ofile = NULL;
				stream->user = NULL;
				ELOG << _("PCAParser: output file is broken.");
			}
		}
		if (stream->server.count_new > 0)
		{
			HttpReqInfo req = HttpReqInfo::fromRequest(stream->server.data,
			                                           stream->server.count_new);
			if (req.Method() != "")
			{
				if (ofile)
				{
					ofile->close();
					delete ofile;
					ofile = NULL;
					stream->user = NULL;
				}
				if (req.Method() == "GET")
				{
					std::stringstream fdir;
					fdir << parse_dir_ << "/";
					fdir << std::setw(16) << std::setfill('0') << std::hex << req.UrlHash();
					check_create_dir(fdir.str());
					VLOG << _("PCAPareser: creating data file.")
					     << _(" Filename: \"") << fdir.str() << "\"";
					ofile = new std::ofstream(fdir.str().c_str(), std::ios::out | std::ios::binary);
					if (ofile->good())
					{
						stream->user = ofile;
					}
					else
					{
						delete ofile;
						ofile = NULL;
						stream->user = NULL;
						ELOG << _("PCAParser: error creating output file.")
						     << _(" Filename: \"") << fdir.str() << "\""
						     << _(" Error message: ") << strerror(errno);
					}
				}
			}
		}
	}
	else
	{
		if (ofile)
		{
			delete ofile;
			ofile = NULL;
			stream->user = NULL;
		}
	}
}

std::string PCAParser::parse_dir_ = ".";

void
PCAParser::Parse(const std::string& input_file, const std::string& output_dir)
{
	parse_dir_ = output_dir;
	nids_params.n_tcp_streams = 4096;
	nids_params.filename = const_cast<char*>(input_file.c_str());
	nids_params.device = NULL;
	nids_params.syslog = (void (*)())PCAParser::nidsLogger;
	nids_params.syslog_level = 1;
	nids_params.scan_num_hosts = 0;
	VLOG << "Initializing PCAParser.";
	if (!nids_init())
	{
		ELOG << _("PCAParser: error initializing NIDS.")
		     << _(" Message: ") << nids_errbuf;
	}
	struct nids_chksum_ctl nocksum = {0, 0, NIDS_DONT_CHKSUM};
	nids_register_chksum_ctl(&nocksum, 1);
	nids_register_tcp((void *)tcpCallback);
	nids_run();
	nids_unregister_tcp((void *)tcpCallback);
	nids_exit();
}

} // namespace

