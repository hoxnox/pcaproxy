/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18 */

#include <ProcessManager.hpp>
#include "PCAParser.hpp"
#include "Config.hpp"
#include <Logger.hpp>
#include <set>
#include <iostream>
#include <gettext.h>

namespace pcaproxy {

ProcessManager::ProcessManager()
{
}

ProcessManager::~ProcessManager()
{
}

bool ProcessManager::doStart()
{
	Config::Ptr cfg = Config::GetInstance();
	PCAParser pcaparser;
	pcaparser.Parse(cfg->Filename(), cfg->ParseDir());
	std::set<std::string> main_reqs;
	pcaparser.GetMainReqs(std::inserter(main_reqs, main_reqs.end()));
	std::string index = 
		"<HTML>"
			"<HEAD>"
				"<TITLE>pcaproxy</TITLE>"
			"<BODY style=\"font-family: Tahoma, Verdana\">"
				"<h1>PCAPROXY</h1>"
				"Links in pcap file \"" + cfg->Filename() + "\" without referers:<br>"
				"<ul>";
	for (auto i = main_reqs.begin(); i != main_reqs.end(); ++i)
		index += "<li/><a href=\"" + *i + "\">" + *i + "</a><br>";
	index +=
			"</ul>"
			"</BODY>"
		"</HTML>";
	proxy_.SetIndex(index.begin(), index.end());
	proxy_thread_.reset(new std::thread(PCAProxy::Loop, &proxy_));
	if (!cfg->Fork())
	{
		std::cout << _("----------[ cut here ]----------") << std::endl;
		std::cout << _("Proxy started. Use these settings in the browser:")
		          << cfg->BindAddr() << std::endl;
		std::cout << _("To stop the proxy server use kill signal (Ctrl+C).")
		          << std::endl;
	}
	return true;
}

bool ProcessManager::doStop()
{
	Config::Ptr cfg = Config::GetInstance();
	proxy_.Stop();
	if (!cfg->DontClean())
	{
		VLOG << ("Removing *.req, *.rsp and *.dat from \"" + cfg->ParseDir() + "\"");
		system((std::string("rm -f \"") + cfg->ParseDir() + "\"/*.req").c_str());
		system((std::string("rm -f \"") + cfg->ParseDir() + "\"/*.rsp").c_str());
		system((std::string("rm -f \"") + cfg->ParseDir() + "\"/*.dat").c_str());
	}
	proxy_thread_->join();
	return true;
}

} // namespace

