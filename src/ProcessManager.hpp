/**@author $username$ <$usermail$>
 * @date $date$ */

#ifndef __PCAPROXY_PROCESS_MANAGER_HPP__
#define __PCAPROXY_PROCESS_MANAGER_HPP__

#include <thread>

#include "Logger.hpp"
#include "Config.hpp"
#include "PCAProxy.hpp"
#include "PCAParser.hpp"
#include <utils/ProcessManagerBase.hpp>

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
	PCAParser                    parser_;
	std::unique_ptr<std::thread> proxy_thread_;
	Config* conf_;
};

} // namespace

#endif // __PCAPROXY_PROCESS_MANAGER_HPP__

