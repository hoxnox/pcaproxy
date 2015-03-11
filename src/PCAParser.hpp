/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __PCAPARSER_HPP__ 
#define __PCAPARSER_HPP__ 

#include <vector>
#include <string>
#include <fstream>
#include <map>
#include <memory>

namespace pcaproxy {

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
private:
	static void        nidsLogger(int type, int err, struct ip *iph, void *data);
	static void        tcpCallback(struct tcp_stream *stream, void** params);
	static std::string                                 parse_dir_;
	static std::shared_ptr<PCAParser>                  instance_;
};

} // namespace


#endif // __PCAPARSER_HPP__

