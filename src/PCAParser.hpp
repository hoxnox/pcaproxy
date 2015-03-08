/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __PCAPARSER_HPP__ 
#define __PCAPARSER_HPP__ 


namespace pcaproxy {

class PCAParser
{
public:
	PCAParser();
private:
	static void nidsLogger(int type, int err, struct ip *iph, void *data);
	static void tcpCallback(struct tcp_stream *stream, void** not_needed);
};

} // namespace


#endif // __PCAPARSER_HPP__

