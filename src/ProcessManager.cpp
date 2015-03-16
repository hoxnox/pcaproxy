/**@author $username$ <$usermail$>
 * @date $date$ */

#include <ProcessManager.hpp>
#include "PCAParser.hpp"
#include "Config.hpp"
#include <Logger.hpp>

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
	PCAParser::Ptr pcaparser = PCAParser::GetInstance();
	pcaparser->Parse(cfg->Filename(), cfg->ParseDir());
	std::vector<std::string> main_reqs;
	pcaparser->GetMainReqs(std::back_inserter(main_reqs));
	std::string index = "<HTML><BODY>";
	for (auto i = main_reqs.begin(); i != main_reqs.end(); ++i)
		index += "<a href=\"" + *i + "\">" + *i + "</a><br>";
	index += "</BODY></HTML>";
	proxy_.SetIndex(index.begin(), index.end());
	proxy_thread_.reset(new std::thread(PCAProxy::Loop, &proxy_));
	return true;
}

bool ProcessManager::doStop()
{
	proxy_.Stop();
	proxy_thread_->join();
	return true;
}

} // namespace

