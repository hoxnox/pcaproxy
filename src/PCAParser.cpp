/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18 */

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

#include <Logger.hpp>
#include <utils/NxSocket.h>
#include <utils/MkDir.h>
#include <utils/Utils.hpp>
#include <gettext.h>

#include "PCAParser.hpp"
#include "HttpReqInfo.hpp"

namespace pcaproxy {

template <class InputIterator> inline void
write_to_file(const std::string& fname, InputIterator begin, InputIterator end, bool append = true)
{
	std::ios::openmode mode = std::ios::binary;
	if (append)
		mode |= std::ios::app;
	else
		mode |= std::ios::out;
	std::ofstream ofile(fname.c_str(), mode);
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
	ofile.close();
}

void
PCAParser::splitHttpRequests(const std::vector<char>& data,
                             std::vector<HttpReqInfo>& result)
{
	const char* end  = &data[data.size()];
	if (data.size() == 0)
		return;
	const char* left = &data[0];
	std::string delim = "\r\n\r\nGET";
	const char* right = std::search(left + 1, end, delim.begin(), delim.end() - 1);
	while (end - right > 7)
	{
		HttpReqInfo ireq(left, right - left);
		left = right + 4;
		right = std::search(left, end, delim.begin(), delim.end());
		if (ireq.Method() != "GET")
			continue;
		if (ireq.Referer().empty())
		{
			VLOG << "Pushing to main: " << ireq.Url();
			main_reqs_.push_back(ireq);
		}
		result.push_back(ireq);
	}

	HttpReqInfo ireq(left, end - left);
	if (ireq.Method() != "GET")
		return;
	if (ireq.Referer().empty())
	{
		VLOG << "Pushing to main: " << ireq.Url();
		main_reqs_.push_back(ireq);
	}
	result.push_back(ireq);
}

void
PCAParser::splitHttpResponses(const std::vector<char>& data,
                              std::vector<std::vector<char> >& result)
{
	if (data.size() == 0)
		return;
	const char* left = &data[0];
	const char* end  = &data[data.size() - 1] + 1;
	const std::string http_ok = "HTTP/1.1 200 OK\r\n";
	const char* right = std::search(left + 1, end, http_ok.begin(), http_ok.end() - 1);
	while (end - right > 17)
	{
		std::vector<char> resp(left, right);
		result.push_back(resp);
		left = right;
		right = std::search(left + 1, end, http_ok.begin(), http_ok.end() - 1);
	}
	std::vector<char> resp(left, end);
	result.push_back(resp);
}

bool
PCAParser::saveToFiles(const std::vector<std::vector<char> >& responses,
                       const std::vector<HttpReqInfo>& requests)
{
	if (responses.size() != requests.size())
	{
		ELOG << _("PCAParser: requests count didn't match responses count"
		          " in the same TCP stream. Trying first-to-first strategy.")
		     << _(" Responses: ") << responses.size()
		     << _(" Requests: ") << requests.size();
	}
	size_t min_size = std::min(requests.size(), responses.size());
	for (size_t i = 0; i < min_size; ++i)
		write_to_file(requests[i].FName(), responses[i].begin(), responses[i].end(), false);
	return true;
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
		if (data_rsp.empty())
			continue;
		std::string req_fname(i->substr(0, i->length() - 4) + ".req");
		if (!read_file(req_fname, std::back_inserter(data_req)))
		{
			ELOG << _("PCAParser: error reading requests file.")
			     << _(" Filename: \"") << req_fname << "\"";
			continue;
		}
		if (data_req.empty())
			continue;
		std::vector<HttpReqInfo> requests;
		splitHttpRequests(data_req, requests);
		std::vector<std::vector<char> > responses;
		splitHttpResponses(data_rsp, responses);
		if (!saveToFiles(responses, requests))
		{
			ELOG << _("PCAParser: error splitting up TCP stream.")
			     << _(" Stream files: \"") << *i << "\" \"" << req_fname << "\"";
			continue;
		}
	}
}

bool
PCAParser::Parse(const std::string& input_file, const std::string& output_dir)
{
	if (!initPCAP(input_file))
		return false;
	parse_dir_ = output_dir; // we must fix parse_dir till parse has finished
	check_create_dir(parse_dir_ + "/");

	ntoh_init();
	unsigned int error;

	tcp_session_.reset(ntoh_tcp_new_session(0, 0, &error));
	if (!tcp_session_)
	{
		ELOG << _("PCAParser: error initializing new tcp session.")
		     << _(" Message: ") << ntoh_get_errdesc(error);
		return false;
	}

	ipv4_session_.reset(ntoh_ipv4_new_session(0, 0, &error));
	if (!ipv4_session_)
	{
		ELOG << _("PCAParser: error initializing new ipv4 session.")
		     << _(" Message: ") << ntoh_get_errdesc(error);
		return false;
	}

	const unsigned char *packet = 0;
	struct pcap_pkthdr header;
	while ((packet = pcap_next(pcap_.get(), &header)) != 0)
	{
		const int SIZE_ETHERNET = 14;
		struct ip* ip = (struct ip*) (packet + SIZE_ETHERNET);
		if ((ip->ip_hl * 4) < sizeof(struct ip))
			continue;
		if (NTOH_IPV4_IS_FRAGMENT(ip->ip_off))
			sendIPv4Fragment(ip);
		else if (ip->ip_p == IPPROTO_TCP)
			sendTCPSegment(ip);
	}
	pcap_.reset(NULL);
	//ntoh_exit(); BROKES SIGNAL

	splitHttp();

	return true;
}

void
PCAParser::tcpCallback(pntoh_tcp_stream_t stream,
                       pntoh_tcp_peer_t orig,
                       pntoh_tcp_peer_t dest,
                       pntoh_tcp_segment_t seg,
                       int reason,
                       int extra)
{
	if (ntohs(dest->port) != 80 && ntohs(orig->port) != 80)
		return;
	PCAParser* this_ = NULL;
	if (stream && stream->udata)
		this_ = reinterpret_cast<PCAParser*>(stream->udata);
	if (!this_)
		ELOG << _("PCAParser: stream doesn't contain user defined data.");
	char* data = NULL;
	if (seg != 0 && seg->user_data)
		data = reinterpret_cast<char*>(seg->user_data);
	if (reason == NTOH_REASON_DATA && data != NULL && this_ != NULL)
	{
		std::stringstream name;
		name << this_->parse_dir_ << '/'
		     << std::setw(sizeof(ntoh_tcp_key_t)*2) << std::setfill('0') << std::hex << stream->key;
		if (ntohs(dest->port) == 80)
			write_to_file(name.str() + ".req", data, data + seg->payload_len);
		else if(ntohs(orig->port) == 80)
			write_to_file(name.str() + ".rsp", data, data + seg->payload_len);
		if (extra != 0)
		{
			ELOG << _("PCAParser: libntoh got extra info in tcpCallback.")
			     << _(" Code: ") << extra
			     << _(" Message: ") << ntoh_get_reason(extra);
		}
	}
	else
	{
		if (extra == NTOH_REASON_MAX_SYN_RETRIES_REACHED
		 || extra == NTOH_REASON_MAX_SYNACK_RETRIES_REACHED
		 || extra == NTOH_REASON_HSFAILED
		 || extra == NTOH_REASON_EXIT
		 || extra == NTOH_REASON_TIMEDOUT
		 || extra == NTOH_REASON_CLOSED)
		{
			//VLOG << _("PCAParser: deleting stream");
		}
	}
	if (data)
		delete [] data;
}

void
PCAParser::ipv4Callback(pntoh_ipv4_flow_t flow,
                        pntoh_ipv4_tuple4_t tuple,
                        unsigned char *data,
                        size_t len,
                        unsigned short reason)
{
	if ( tuple->protocol == IPPROTO_TCP )
	{
		if(flow && flow->udata)
		{
			PCAParser *this_ = reinterpret_cast<PCAParser*>(flow->udata);
			this_->sendTCPSegment((struct ip*)data);
		}
	}
	return;

}

void
PCAParser::sendTCPSegment(struct ip *iphdr)
{
	unsigned int error;

	size_t size_ip = iphdr->ip_hl * 4;
	struct tcphdr* tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
	size_t size_tcp = tcp->th_off * 4;
	if (size_tcp < sizeof(struct tcphdr))
		return;
	ntoh_tcp_tuple5_t tcpt5;
	ntoh_tcp_get_tuple5(iphdr, tcp ,&tcpt5);

	if (ntohs(tcpt5.sport) != 80 && ntohs(tcpt5.dport) != 80)
		return;

	pntoh_tcp_stream_t stream = ntoh_tcp_find_stream(tcp_session_.get(), &tcpt5);
	if (!stream)
	{
		stream = ntoh_tcp_new_stream(tcp_session_.get(), &tcpt5, tcpCallback, this, &error, 1, 1);
		if (!stream)
		{
			ELOG << _("PCAParser: error creating new stream.")
			     << _(" Message: ") << ntoh_get_errdesc(error);
			return;
		}
	}

	size_t total_len = ntohs(iphdr->ip_len);
	size_t size_payload = total_len - ( size_ip + size_tcp );
	char* payload = NULL;
	if (size_payload > 0)
	{
		payload = new char[size_payload];
		char* payload_pos = (char *)iphdr + size_ip + size_tcp; 
		std::copy(payload_pos, payload_pos + size_payload, payload);
	}

	int rs = ntoh_tcp_add_segment(tcp_session_.get(), stream, iphdr, total_len, payload);
	if (rs != NTOH_OK)
	{
		if (rs != NTOH_SYNCHRONIZING)
		{
			VLOG << _("PCAParser: error adding TCP segment.")
			     << _(" Message: ") << ntoh_get_retval_desc(rs);
		}
		if (payload)
			delete [] payload;
	}
}

void
PCAParser::sendIPv4Fragment(struct ip *iphdr)
{
	unsigned int error;

	ntoh_ipv4_tuple4_t ipt4;
	ntoh_ipv4_get_tuple4(iphdr , &ipt4);
	pntoh_ipv4_flow_t flow = ntoh_ipv4_find_flow(ipv4_session_.get() , &ipt4);
	if (!flow)
	{
		flow = ntoh_ipv4_new_flow(ipv4_session_.get(), &ipt4, ipv4Callback, this, &error);
		if (!flow)
		{
			ELOG << _("PCAParser: error creating new IPv4 flow.")
			     << _("Message: ") << ntoh_get_errdesc(error);
			return;
		}
	}

	size_t total_len = ntohs(iphdr->ip_len);
	int rs = ntoh_ipv4_add_fragment(ipv4_session_.get(), flow, iphdr, total_len);
	if (rs)
	{
		ELOG << _("PCAParser: error adding IPv4 to flow.")
		     << _(" Message: ") << ntoh_get_retval_desc(rs);
	}
}

bool
PCAParser::initPCAP(std::string fname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_.reset(pcap_open_offline(fname.c_str(), errbuf));
	if (!pcap_)
	{
		ELOG << _("PCAParser: error pcap initialization.")
		     << _(" Message: ") << errbuf;
		return false;
	}
	struct bpf_program fp;
	if (pcap_compile(pcap_.get(), &fp, "tcp and port 80", 0, 0) < 0)
	{
		ELOG << _("PCAParser: error initializing pcap filter.")
		     << _(" Message: ") << pcap_geterr(pcap_.get());
		return false;
	}
	if (pcap_setfilter(pcap_.get(), &fp) < 0)
	{
		ELOG << _("PCAParser: Error pcap filter apply.")
		     << _(" Message: ") << pcap_geterr(pcap_.get());
		pcap_freecode(&fp);
		return false;
	}
	pcap_freecode(&fp);
	if (pcap_datalink(pcap_.get()) != DLT_EN10MB)
	{
		ELOG << _("PCAParser: Link layer is not Ethernet.");
		return false;
	}
	VLOG << _("PCAParser: libpcap inititalized.")
	     << _(" File: \"") << fname << "\""
	     << _(" Desc: ") << pcap_datalink_val_to_description(pcap_datalink(pcap_.get()));
	return true;
}


} // namespace

