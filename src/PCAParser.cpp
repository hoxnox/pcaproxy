/**@author $username$ <$usermail$>
 * @date $date$ */


#include <nids.h>
#include "PCAParser.hpp"
#include "HttpReqInfo.hpp"
#include "Config.hpp"

#include <Logger.hpp>
#include <Endians.hpp>
#include <utils/NxSocket.h>
#include <utils/MkDir.h>
#include <utils/Utils.hpp>
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
addr_info(const struct tuple4& addr, std::string delim = "vs")
{
	std::stringstream ss;
	ss << inet_ntos(addr.saddr) << ":" << addr.source;
	ss << " " << delim << " ";
	ss << inet_ntos(addr.daddr) << ":" << addr.dest;
	return ss.str();
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
			HttpReqInfo req(stream->server.data, stream->server.count_new);
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
					check_create_dir(req.FName());
					VLOG << _("PCAPareser: creating data file.")
					     << _(" Filename: \"") << req.FName() << "\""
						 << _(" URL: ") << req.Url();
					ofile = new std::ofstream(req.FName(), std::ios::out | std::ios::binary);
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
						     << _(" Filename: \"") << req.FName() << "\""
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

