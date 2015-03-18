/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18*/

#ifndef __PCAPARSER_HPP__ 
#define __PCAPARSER_HPP__ 

#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <functional>
#include <map>
#include <memory>

#include <pcap.h>
#include <libntoh/libntoh.h>
#include <HttpReqInfo.hpp>

namespace pcaproxy {

class PCAParser
{
public:
	PCAParser();
	bool Parse(const std::string& input_file, const std::string& output_dir);
	template<class OutIter> void GetMainReqs(OutIter out) const;
private:
	static void tcpCallback(pntoh_tcp_stream_t stream,
	                        pntoh_tcp_peer_t orig,
	                        pntoh_tcp_peer_t dest,
	                        pntoh_tcp_segment_t seg,
	                        int reason,
	                        int extra);
	static void ipv4Callback(pntoh_ipv4_flow_t flow,
	                         pntoh_ipv4_tuple4_t tuple,
	                         unsigned char *data,
	                         size_t len,
	                         unsigned short reason);
	void sendTCPSegment(struct ip *iphdr);
	void sendIPv4Fragment(struct ip *iphdr);
	bool initPCAP(std::string fname);
	void splitHttp();
	void splitHttpRequests(const std::vector<char>& data,
	                       std::vector<HttpReqInfo>& result);
	void splitHttpResponses(const std::vector<char>& data,
	                        std::vector<std::vector<char> >& result);
	bool saveToFiles(const std::vector<std::vector<char> >& responses,
	                 const std::vector<HttpReqInfo>& requests);

	std::vector<HttpReqInfo>                    main_reqs_;
	std::string                                 parse_dir_;
	std::unique_ptr<pcap_t, void(&)(pcap_t*)>   pcap_;
	std::unique_ptr<ntoh_tcp_session_t, void(&)(ntoh_tcp_session_t*)>   tcp_session_;
	std::unique_ptr<ntoh_ipv4_session_t, void(&)(ntoh_ipv4_session_t*)> ipv4_session_;
};

////////////////////////////////////////////////////////////////////////
// inline

inline
PCAParser::PCAParser()
	: pcap_(NULL, pcap_close)
	, tcp_session_(NULL, ntoh_tcp_free_session)
	, ipv4_session_(NULL, ntoh_ipv4_free_session)
{
}

template<class OutIter> inline void
PCAParser::GetMainReqs(OutIter out) const 
{
	std::for_each(main_reqs_.begin(), main_reqs_.end(),
			[&out](const HttpReqInfo& req) { *out++ = req.Url(); });
}


} // namespace

#endif // __PCAPARSER_HPP__

