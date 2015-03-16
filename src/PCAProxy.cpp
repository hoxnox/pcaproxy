/**@author $username$ <$usermail$>
 * @date $date$ */

#include "PCAProxy.hpp"
#include "HttpReqInfo.hpp"

#include <Logger.hpp>
#include <Config.hpp>
#include <utils/Utils.hpp>

#include <gettext.h>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>

namespace pcaproxy {

inline int init_sock(const struct sockaddr_storage& addr)
{
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if(!IS_VALID_SOCK(sock))
	{
		ELOG << _("Error socket initializing.")
		     << _(" Message: ") << strerror(GET_LAST_SOCK_ERROR());
		return INVALID_SOCKET;
	}
	if (SetNonBlock(sock) < 0)
	{
		ELOG << _("Error switching socket to non-blocking mode.")
		     <<  _(" Message: ") << strerror(GET_LAST_SOCK_ERROR());
		return INVALID_SOCKET;
	}
	if (SetReusable(sock) < 0)
	{
		ELOG << _("Error making socket reusable.")
		     << _(" Message: ") << strerror(GET_LAST_SOCK_ERROR());
		return INVALID_SOCKET;
	}
	if (bind(sock, (sockaddr *)&addr, sizeof(addr)) != 0)
	{
		ELOG << _("Error socket binding.")
		     << _("Message: ") << strerror(GET_LAST_SOCK_ERROR());
		return INVALID_SOCKET;
	}
	return sock;
}

void PCAProxy::heartbeat(int, short int, void *self)
{
	//VLOG << "Heartbeat";
	if (!self)
		return;
	PCAProxy* this_ = reinterpret_cast<PCAProxy*>(self);
	if (this_->stop_)
	{
		event_base_loopbreak(this_->evbase_.get());
		return;
	}
	Config::Ptr cfg = Config::GetInstance();
	struct timeval tv = cfg->Tick();
	event_add(this_->evtimeout_.get(), &tv);
	return;
}

PCAProxy::PCAProxy()
	: stop_(true)
	, evbase_(event_base_new(), event_base_free)
	, evtimeout_(event_new(evbase_.get(), 0, EV_TIMEOUT, heartbeat, this), event_free)
	, evhttp_(NULL, evhttp_free)
	, evbuf_(evbuffer_new(), evbuffer_free)
{
}

void
PCAProxy::onRequest(struct evhttp_request * evreq, void * arg)
{
	if(!arg)
	{
		ELOG << _("onRequest bad arg value");
		return;
	}
	if(!evreq)
		return;
	PCAProxy *this_ = reinterpret_cast<PCAProxy*>(arg);
	if (evreq->type != EVHTTP_REQ_GET)
	{
		evhttp_send_error(evreq, HTTP_BADREQUEST, "Can't handle the query.");
		return;
	}
	HttpReqInfo req(std::string(evreq->uri));
	VLOG << _("PCAProxy: received HTTP request.")
	     << _(" Method: ") << req.Method()
	     << _(" UrlHash: ") << req.UrlHash()
	     << _(" URL: ") << req.Url();
	std::ifstream ifile(req.FName(), std::ios::in | std::ios::binary);
	if (!ifile.good())
	{
		VLOG << _("PCAProxy: no file corresponds.")
		     << _(" FileName: ") << req.FName()
		     << _(" URL: ") << req.Url();
		evbuffer_add(this_->evbuf_.get(), &this_->index_page_[0],
		                                  this_->index_page_.size());
		evhttp_send_reply(evreq, HTTP_OK, "", this_->evbuf_.get());
		return;
	}
	std::vector<char> header_raw;
	std::istreambuf_iterator<char> reader(ifile.rdbuf());
	for (;reader != std::istreambuf_iterator<char>(); ++reader)
	{
		header_raw.push_back(*reader);
		if (std::string(header_raw.rbegin(), header_raw.rbegin() + 4) == "\n\r\n\r")
			break;
	}
	++reader;
	std::streampos curpos = ifile.tellg();
	ifile.seekg(0, std::ios_base::end);
	std::streampos endpos = ifile.tellg();
	ifile.seekg(curpos);
	ssize_t body_size_n = endpos - curpos;
	std::stringstream ss;
	ss << body_size_n;
	std::string body_size = ss.str();

	std::vector<std::string> hlines;
	split(std::string(header_raw.begin(), header_raw.end()),
	      std::back_inserter(hlines), "\r\n", true);

	for (auto i = hlines.begin() + 1; i != hlines.end(); ++i)
	{
		ssize_t colon_pos = i->find_first_of(':');
		if (colon_pos == std::string::npos)
		{
			ELOG << _("PCAProxy: wrong file structure."
			          " Can't find colon in the header line.")
			     << _(" Filename: ") << req.FName()
			     << _(" Line: ") << *i;
			evhttp_send_error(evreq, 500, "Datafile has wrong structure.");
			return;
		}
		std::string key = i->substr(0, colon_pos);
		std::string val = i->substr(colon_pos + 1, i->length() - colon_pos -1);
		if (tolower(key) != "connection")
			evhttp_add_header(evreq->output_headers, key.c_str(), val.c_str());
		//VLOG << _("PCAProxy: header line: ") << key << ": " << val;
	}

	std::vector<char> fbuf;
	std::copy(reader, std::istreambuf_iterator<char>(), std::back_inserter(fbuf));
	evbuffer_add(this_->evbuf_.get(), &fbuf[0], fbuf.size());
	evhttp_send_reply(evreq, HTTP_OK, "", this_->evbuf_.get());
	return;
}

void
PCAProxy::Loop(PCAProxy* this_)
{
	if (this_->stop_ != true)
	{
		ELOG << _("Attempt to Loop() already running PCAProxy instance.");
		return;
	}
	this_->stop_ = false;
	Config::Ptr cfg = Config::GetInstance();
	struct timeval tv = cfg->Tick();
	SOCKET sock = init_sock(Config::Str2Inaddr(cfg->BindAddr()));
	if (!IS_VALID_SOCK(sock))
		return;
	if (listen(sock, cfg->Backlog()) == -1)
	{
		ELOG << _("Error listening.")
		     << _(" Message: ") << GET_LAST_SOCK_ERROR();
		return;
	}
	this_->evhttp_.reset(evhttp_new(this_->evbase_.get()));
	if (evhttp_accept_socket(this_->evhttp_.get(), sock) == -1) {
		ILOG << "Error evhttp_accept_socket(): "
		     << strerror(errno) << std::endl;
		return;
	}
	evhttp_set_gencb(this_->evhttp_.get(), PCAProxy::onRequest, this_);
	event_add(this_->evtimeout_.get(), &tv);
	event_base_dispatch(this_->evbase_.get());
	return;
}

} // namespace

