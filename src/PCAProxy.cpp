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

PCAProxy::PCAProxy()
	: stop_(true)
{
}

void 
PCAProxy::sendHttpResp(int sock, int code, const std::string& msg)
{
	std::stringstream ss;
	ss << "HTTP1/1 " << code << " " << msg << "\r\n";
	if (sock != INVALID_SOCKET)
		send(sock, ss.str().c_str(), ss.str().length(), 0);
}

void
PCAProxy::onRequest(int sock)
{
	char buf[0x10000];
	VLOG << "Request here!";
	ssize_t rs = read(sock, buf, sizeof(buf));
	while(true)
	{
		if (rs == -1)
		{
			ELOG << _("PCAProxy: error reading HTTP request.")
			     << _(" Message: ") << strerror(errno);
			sendHttpResp(sock, 500, "Error reading data");
			return;
		}
		if (rs == 0)
			return;
		HttpReqInfo req(buf, rs);
		if (req.Method() == "")
		{
			VLOG << _("PCAProxy: received strange request.")
			     << _(" Dump: ") << byte2str(buf, rs);
			sendHttpResp(sock, 400, "Bad request");
			return;
		}
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
			sendHttpResp(sock, 404, "Not found");
			return;
		}
		std::istreambuf_iterator<char> reader(ifile.rdbuf());
		std::vector<char> fbuf;
		std::copy(reader, std::istreambuf_iterator<char>(), std::back_inserter(fbuf));
		rs = send(sock, &fbuf[0], fbuf.size(), 0);
		if (rs != fbuf.size())
		{
			ELOG << _("PCAProxy: error sending data.")
			     << _(" Sent: ") << rs
			     << _(" Message: ") << strerror(errno)
			     << _(" FileName: ") << req.FName()
			     << _(" URL: ") << req.Url();
				return;
		}
	}
}

void
PCAProxy::responseLoop(PCAProxy* this_)
{
	Config::Ptr cfg = Config::GetInstance();
	while(!this_->stop_)
	{
		struct timeval tv = cfg->Tick();
		fd_set rdfs, exfs;
		int max = 0;
		FD_ZERO(&rdfs);
		{
			std::lock_guard<std::mutex> lock(this_->connected_mtx_);
			for (auto i = this_->connected_.begin(); i != this_->connected_.end(); ++i)
			{
				FD_SET(*i, &rdfs);
				FD_SET(*i, &exfs);
			}
			if (!this_->connected_.empty())
				max = *this_->connected_.rbegin() + 1;
		}
		int rs = select(max, &rdfs, NULL, &exfs, &tv);
		if (rs == -1)
		{
			ELOG << _("PCAProxy: error calling select in reponseLoop.")
			     << _(" Message: ") << strerror(errno);
			this_->Stop();
			break;
		}
		if (rs == 0)
		{
			// VLOG << _("PCAProxy: Heartbeat");
			continue;
		}
		{
			std::lock_guard<std::mutex> lock(this_->connected_mtx_);
			for(auto i = this_->connected_.begin(); i != this_->connected_.end(); ++i)
			{
				if (FD_ISSET(*i, &exfs))
				{
					VLOG << _("PCAParser: closing connection ") << *i;
					shutdown(*i, SHUT_RDWR);
					close(*i);
					this_->connected_.erase(i);
				}
				if (FD_ISSET(*i, &rdfs))
				{
					onRequest(*i);
				}
			}
		}
	}
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
	SOCKET sock = init_sock(Config::Str2Inaddr(cfg->BindAddr()));
	if (!IS_VALID_SOCK(sock))
		return;
	if (listen(sock, cfg->Backlog()) == -1)
	{
		ELOG << _("Error listening.")
		     << _(" Message: ") << GET_LAST_SOCK_ERROR();
		return;
	}
	std::thread response_thread(responseLoop, this_);
	while (!this_->stop_)
	{
		fd_set rdfs;
		FD_ZERO(&rdfs);
		FD_SET(sock, &rdfs);
		struct timeval tv = cfg->Tick();
		int rs = select(sock+1, &rdfs, NULL, NULL, &tv);
		if (rs == -1)
		{
			ELOG << _("PCAProxy: error calling select.")
			     << _(" Message: ") << strerror(errno);
			this_->Stop();
			break;
		}
		if (rs == 0)
		{
			// VLOG << _("PCAProxy: Heartbeat");
			continue;
		}
		struct sockaddr_storage raddr;
		memset(&raddr, 0, sizeof(raddr));
		socklen_t raddrlen = sizeof(raddr);
		int nsock = accept(sock, (struct sockaddr*)&raddr, &raddrlen);
		if (nsock == -1)
		{
			ELOG << _("PCAProxy: error calling accept.")
			     << _(" Message: ") << strerror(errno);
		}
		else
		{
			std::lock_guard<std::mutex> lock(this_->connected_mtx_);
			this_->connected_.insert(nsock);
		}
	}
	response_thread.join();
}

} // namespace

