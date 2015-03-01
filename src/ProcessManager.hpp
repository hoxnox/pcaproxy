/**@author $username$ <$usermail$>
 * @date $date$ */

#ifndef __PCAPROXY_PROCESS_MANAGER_HPP__
#define __PCAPROXY_PROCESS_MANAGER_HPP__

#include <utils/ProcessManagerBase.hpp>

#include <Logger.hpp>
#include <Config.hpp>
#include <PCAProxy.hpp>
#include <thread>

namespace pcaproxy {

class ProcessManager : public ProcessManagerBase
{
public:
	ProcessManager();
	~ProcessManager();
protected:
	virtual bool                 doStart();
	virtual bool                 doStop();
	PCAProxy                     proxy_;
	std::unique_ptr<std::thread> proxy_thread_;
	Config* conf_;
};

} // namespace

#endif // __PCAPROXY_PROCESS_MANAGER_HPP__

