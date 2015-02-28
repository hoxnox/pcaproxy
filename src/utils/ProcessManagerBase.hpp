/* @author $username$ <$usermail$>
 * @date 20130529 20:56:21 */

#ifndef __PCAPROXY_PROCESS_MANAGER_BASE__ 
#define __PCAPROXY_PROCESS_MANAGER_BASE__ 

#include <memory>
#include <thread>
#include <mutex>
#include <signal.h>

namespace pcaproxy {

class ProcessManagerBase
{
public:
	enum State
	{
		STATE_NULL      = 0,
		STATE_RUNNING   = 2,
		STATE_RUNNING_D = 3,
	};
	ProcessManagerBase();
	~ProcessManagerBase() {};
	void            Dispatch();
	void            Loop();
	void            Stop();
	State           GetState() const { return state_; }

protected:
	virtual bool    doStart() = 0;
	virtual bool    doStop() = 0;

private:
	void         loop();
	static void* start_loop(void* process_manager);
	static void  signalError(int sig, siginfo_t *si, void *ptr);
	void         setupSignals(sigset_t& sigset);
	State                        state_;
	sigset_t                     sigset_;
	std::mutex                   state_mtx_;
	std::unique_ptr<std::thread> thread_;
};


} // pcaproxy

#endif // __PCAPROXY_PROCESS_MANAGER_BASE__ 

