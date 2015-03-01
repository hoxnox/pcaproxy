/**@author $username$ <$usermail$>
 * @date $date$ */

#include <ProcessManager.hpp>
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

