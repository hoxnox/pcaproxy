/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __PCAPARSER_HPP__ 
#define __PCAPARSER_HPP__ 

#include <vector>
#include <string>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <HttpReqInfo.hpp>

namespace pcaproxy {

/**
 * @warning Is NOT thread safe because parse_dir_ is static and is used by
 * the Parse function..*/
class PCAParser
{
public:
	void Parse(const std::string& input_file, const std::string& output_dir);
	typedef std::shared_ptr<PCAParser> Ptr;
	static Ptr GetInstance()
	{
		if (!instance_)
			instance_.reset(new PCAParser);
		return instance_;
	}
	template<class OutIter>
	void GetMainReqs(OutIter out) const;
private:
	static void nidsLogger(int type, int err, struct ip *iph, void *data);
	static void tcpCallback(struct tcp_stream *stream, void** params);
	static void splitHttp();
	static void splitHttpRequests(const std::vector<char>& data,
	                              std::vector<HttpReqInfo>& result);
	static void splitHttpResponses(const std::vector<char>& data,
	                               std::vector<std::vector<char> >& result);
	static bool saveToFiles(const std::vector<std::vector<char> >& responses,
	                        const std::vector<HttpReqInfo>& requests);
	static std::string                                 parse_dir_;
	static std::shared_ptr<PCAParser>                  instance_;
	static std::vector<HttpReqInfo>                    main_reqs_;
};

template<class OutIter> inline void
PCAParser::GetMainReqs(OutIter out) const 
{
	std::for_each(main_reqs_.begin(), main_reqs_.end(),
			[&out](const HttpReqInfo& req) { *out++ = req.Url(); });
}

} // namespace

#endif // __PCAPARSER_HPP__

