/**@author $username$ <$usermail$>
 * @date $date$ */

#include "PCAProxy.hpp"

#include <Logger.hpp>
#include <Config.hpp>
#include <utils/NxSocket.h>

#include <gettext.h>
#include <cstring>

namespace pcaproxy {

/**@brief Socket initialization*/
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

PCAProxy::PCAProxy()
	: stop_(true)
	, evbase_(event_base_new(), event_base_free)
	, evtimeout_(event_new(evbase_.get(), 0, EV_TIMEOUT, heartbeat, this), event_free)
	, evhttp_(NULL, evhttp_free)
	, evbuf_(evbuffer_new(), evbuffer_free)
{
	Config::Ptr cfg = Config::GetInstance();
}

void PCAProxy::heartbeat(int, short int, void *self)
{
	VLOG << "Heartbeat";
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

/**@brief OnRequest callback
 *
 * Fires, when request is coming*/
void
PCAProxy::onRequest(struct evhttp_request * req, void * arg)
{
	if(!arg)
	{
		ELOG << _("onRequest bad arg value");
		return;
	}
	if(!req)
		return;
	PCAProxy *this_ = reinterpret_cast<PCAProxy*>(arg);
	VLOG << _("Request handling: ") << req->uri;
	std::string answer = "Hello, world!";
	evbuffer_add(this_->evbuf_.get(), answer.c_str(), answer.length());
    evhttp_send_reply(req, HTTP_OK, "", this_->evbuf_.get());
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
	Config::Ptr cfg = Config::GetInstance();
	struct timeval tv = cfg->Tick();
	this_->stop_ = false;
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

