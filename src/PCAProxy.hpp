/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18 */

#ifndef   __PCAPROXY_HPP__
#define   __PCAPROXY_HPP__

#include <memory>
#include <functional>
#include <string>
#include <utils/NxSocket.h>
#include <event.h>
#include <evhttp.h>
#include <vector>

namespace pcaproxy {

class PCAProxy
{
public:
	PCAProxy();
	template <class InIter>
	void SetIndex(InIter begin, InIter end) { index_page_.assign(begin, end); }
	static void Loop(PCAProxy* this_);
	void Stop() { stop_ = true; }
private:
	static void onRequest(struct evhttp_request * req, void * arg);
	static void heartbeat(int, short int, void* this_);
	bool                                              stop_;
	std::vector<char>                                 index_page_;
	std::unique_ptr<event_base, void(&)(event_base*)> evbase_;
	std::unique_ptr<event, void(&)(event*)>           evtimeout_;
	std::unique_ptr<evhttp, void(&)(evhttp*)>         evhttp_;
	std::unique_ptr<evbuffer, void(&)(evbuffer*)>     evbuf_;
};

} // namespace

#endif // __PCAPROXY_HPP__

