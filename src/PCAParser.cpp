/**@author $username$ <$usermail$>
 * @date $date$ */


#include <nids.h>
#include "PCAParser.hpp"
#include "Config.hpp"

#include <Logger.hpp>
#include <Endians.hpp>
#include <utils/NxSocket.h>
#include <gettext.h>

#include <cstring>
#include <string>
#include <sstream>

namespace pcaproxy {

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

void
PCAParser::tcpCallback(struct tcp_stream *stream, void** not_needed)
{
	if (stream->addr.dest != 80 && stream->addr.source != 80)
	{
		VLOG << _("PCAParser: skipping traffic: ") << addr_info(stream->addr);
		return;
	}
	if (stream->nids_state == NIDS_JUST_EST)
	{
		stream->client.collect++;
		stream->server.collect++;
		VLOG << _("PCAParser: TCP ESTABLISHED: ") << addr_info(stream->addr);
		return;
	}
	if (stream->nids_state == NIDS_CLOSE)
	{
		VLOG << _("PCAParser: TCP CLOSED: ") << addr_info(stream->addr);
		return;
	}
	if (stream->nids_state == NIDS_RESET)
	{
		VLOG << _("PCAParser: TCP RESETED: ") << addr_info(stream->addr);
		return;
	}
	if (stream->nids_state == NIDS_DATA)
	{
		std::string delim;
		struct half_stream* hlf;
		if (stream->client.count_new)
		{
			delim = "<-";
			hlf = &stream->client;
		}
		else
		{
			delim = "->";
			hlf = &stream->server;
		}
		VLOG << _("PCAParser: TCP DATA: ") << addr_info(stream->addr, delim)
		     << _(" Dump: ") << byte2str(hlf->data, hlf->count);
	}
	else
	{
		ELOG << _("PCAParser: unknown NIDS state.")
		     << _(" State: ") << stream->nids_state;
	}
}

PCAParser::PCAParser()
{
	Config::Ptr cfg = Config::GetInstance();
	nids_params.n_tcp_streams = 4096;
	nids_params.filename = const_cast<char*>(cfg->Filename().c_str());
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
	nids_register_tcp((void *)PCAParser::tcpCallback);
	nids_run();
}

} // namespace

