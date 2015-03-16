/**@author $username$ <$usermail$>
 * @date $date$ */

#ifndef   __PCAPROXY_HPP__
#define   __PCAPROXY_HPP__

#include <memory>
#include <functional>
#include <string>
#include <utils/NxSocket.h>
#include <event.h>
#include <evhttp.h>

namespace pcaproxy {

class PCAProxy
{
public:
	PCAProxy();
	static void Loop(PCAProxy* this_);
	void Stop() { stop_ = true; }
private:
	static void onRequest(struct evhttp_request * req, void * arg);
	static void heartbeat(int, short int, void* this_);
	bool                                              stop_;
	std::unique_ptr<event_base, void(&)(event_base*)> evbase_;
	std::unique_ptr<event, void(&)(event*)>           evtimeout_;
	std::unique_ptr<evhttp, void(&)(evhttp*)>         evhttp_;
	std::unique_ptr<evbuffer, void(&)(evbuffer*)>     evbuf_;
};

} // namespace

#endif // __PCAPROXY_HPP__

