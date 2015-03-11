/**@author $username$ <$usermail$>
 * @date $date$ */

#ifndef   __PCAPROXY_HPP__
#define   __PCAPROXY_HPP__

#include <memory>
#include <functional>
#include <string>
#include <set>
#include <utils/NxSocket.h>

namespace pcaproxy {

class PCAProxy
{
public:
	PCAProxy();
	static void Loop(PCAProxy* this_);
	void Stop() { stop_ = true; }
private:
	static void onRequest(int sock, struct sockaddr_storage raddr);
	static std::hash<std::string> hashFun_;
	bool stop_;
};

} // namespace

#endif // __PCAPROXY_HPP__

