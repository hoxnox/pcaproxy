/**@author $username$ <$usermail$>
 * @date $date$ */

#ifndef   __PCAPROXY_HPP__
#define   __PCAPROXY_HPP__

#include <memory>
#include <functional>
#include <string>
#include <set>
#include <utils/NxSocket.h>
#include <thread>
#include <set>
#include <mutex>

namespace pcaproxy {

class PCAProxy
{
public:
	PCAProxy();
	static void Loop(PCAProxy* this_);
	void Stop() { stop_ = true; }
private:
	static void onRequest(int sock);
	static void responseLoop(PCAProxy* self);
	static void sendHttpResp(int sock, int code, const std::string& msg);
	static std::hash<std::string> hashFun_;
	std::set<int>                 connected_;
	std::mutex                    connected_mtx_;
	bool stop_;
};

} // namespace

#endif // __PCAPROXY_HPP__

