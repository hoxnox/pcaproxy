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

template <class InputIterator> inline void
append_to_file(const std::string& fname, InputIterator begin, InputIterator end)
{
	std::ofstream ofile(fname.c_str(), std::ios::binary | std::ios::app);
	if (ofile.good())
	{
		std::ostreambuf_iterator<char> writer(ofile.rdbuf());
		std::copy(begin, end, writer);
	}
	else
	{
		ELOG << _("PCAParser: cannot open file for append.")
		     << _(" Filename: \"") << fname << "\"";
	}
}

void
PCAParser::tcpCallback(struct tcp_stream *stream, void** params)
{
	if (stream->addr.dest != 80 && stream->addr.source != 80)
	{
		VLOG << _("PCAParser: skipping traffic: ") << addr_info(stream->addr);
		return;
	}
	char* udata = reinterpret_cast<char*>(stream->user);
	if (stream->nids_state == NIDS_JUST_EST)
	{
		stream->client.collect++;
		stream->server.collect++;
		std::stringstream ss;
		ss << parse_dir_ << "/";
		ss << std::setw(sizeof(stream->hash_index)*2)
			<< std::setfill('0') << std::hex << stream->hash_index;
		std::string new_prefix = ss.str();
		if (check_create_dir(new_prefix))
		{
			udata = new char[new_prefix.length() + 1];
			std::uninitialized_fill(udata, udata + new_prefix.length() + 1, 0);
			std::copy(new_prefix.begin(), new_prefix.end(), udata);
			stream->user = udata;
		}
		return;
	}
	else if (stream->nids_state == NIDS_DATA)
	{
		std::string fprefix;
		if (stream->user != NULL)
			fprefix.assign(reinterpret_cast<char*>(stream->user));
		if (!fprefix.empty())
		{
			if (stream->client.count_new > 0)
			{
				append_to_file(fprefix + ".rsp", stream->client.data,
					stream->client.data + stream->client.count_new);
			}
			if (stream->server.count_new > 0)
			{
				append_to_file(fprefix + ".req", stream->server.data,
					stream->server.data + stream->server.count_new);
			}
		}
	}
	else
	{
		if (stream->user)
		{
			delete [] udata;
			stream->user = NULL;
		}
	}
}

std::string PCAParser::parse_dir_ = ".";

void
PCAParser::splitHttpRequests(const std::vector<char>& data,
                             std::vector<HttpReqInfo>& result)
{
	std::string str_req(data.begin(), data.end());
	std::vector<std::string> requests;
	split(str_req, std::back_inserter(requests), "\r\n\r\n", true);
	for (auto req = requests.begin(); req != requests.end(); ++req)
	{
		HttpReqInfo ireq(*req);
		result.push_back(ireq);
	}
}

void
PCAParser::splitHttpResponses(const std::vector<char>& data,
                              std::vector<HttpResponse>& result)
{
}

bool
PCAParser::saveToFiles(const std::vector<HttpResponse>& responses,
                       const std::vector<HttpReqInfo>& requests)
{
	Config::Ptr cfg = Config::GetInstance();
	if (responses.size() != requests.size())
	{
		VLOG << _("PCAParser: requests count didn't match responses count"
		          " in the same TCP stream.");
		return false;
	}
	for (size_t i = 0; i < requests.size(); ++i)
	{
		std::string fname = cfg->ParseDir() + "/" + requests[i].UrlHash() + ".dat";
		append_to_file(fname.c_str(), responses[i].data.begin(),
		                              responses[i].data.end());
	}
}

void
PCAParser::splitHttp()
{
	std::vector<std::string> rsp_fnames;
	if (!wheel_dir(parse_dir_, std::back_inserter(rsp_fnames), std::regex(".*\\.rsp$")))
	{
		ELOG << _("PCAParser: error reading direcotry.")
		     << _(" Dirname: \"") << parse_dir_  << "\"";
	}
	for (auto i = rsp_fnames.begin(); i != rsp_fnames.end(); ++i)
	{
		std::vector<char> data_rsp, data_req;
		if (!read_file(*i, std::back_inserter(data_rsp)))
		{
			ELOG << _("PCAParser: error reading responses file.")
			     << _(" Filename: \"") << *i << "\"";
			continue;
		}
		std::string req_fname(i->substr(0, i->length() - 4) + ".req");
		if (!read_file(req_fname, std::back_inserter(data_req)))
		{
			ELOG << _("PCAParser: error reading requests file.")
			     << _(" Filename: \"") << req_fname << "\"";
			continue;
		}
		std::vector<HttpReqInfo> requests;
		splitHttpRequests(data_req, requests);
		std::vector<HttpResponse> responses;
		splitHttpResponses(data_rsp, responses);
		if (!saveToFiles(responses, requests))
		{
			ELOG << _("PCAParser: error splitting up TCP stream.")
			     << _(" Stream files: \"") << *i << "\" \"" << req_fname << "\"";
			continue;
		}
	}
}

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
	splitHttp();
}

} // namespace

