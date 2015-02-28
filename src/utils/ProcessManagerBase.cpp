/* @author $username$ <$usermail$>
 * @date 20130529 20:56:21 */

#include "ProcessManagerBase.hpp"
#include <Logger.hpp>

#include <sstream>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <execinfo.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>
#include <gettext.h>

namespace pcaproxy {

#ifndef VLOG
	struct SimpleLogStream
	{
	public:
		std::stringstream& _stream()
		{
			ss_.str("");
			ss_ << time(NULL) << " ";
			return ss_;
		}
		SimpleLogStream& operator< (std::ostream& ss)
		{
			std::clog << ss.rdbuf() << std::endl;
			return *this;
		}
		static const bool verbose = false;
	protected:
		std::stringstream ss_;
	} __simple_log_strm;
	struct SimpleErrStream : public SimpleLogStream
	{
	public:
		SimpleLogStream& operator< (std::ostream& ss)
		{
			std::cerr << ss.rdbuf() << std::endl;
			return *this;
		}
	} __simple_err_stream;
	class SilentNoop{
	public:
		SilentNoop() { }
		void operator&(SimpleLogStream&) { }
	};
	#define VLOG !SimpleLogStream::verbose ? (void)0 : SilentNoop() & __simple_log_strm < __simple_log_strm._stream()
	#define ILOG SilentNoop() & __simple_log_strm < __simple_log_strm._stream()
	#define ELOG SilentNoop() & __simple_err_strm < __simple_log_strm._stream()
#endif

#ifndef _
#	define _(x) (x)
#endif

ProcessManagerBase::ProcessManagerBase()
	: state_(STATE_NULL)
{
}

void
ProcessManagerBase::signalError(int sig, siginfo_t *si, void *ptr)
{
	void*  ErrorAddr;
	void*  Trace[16];
	int    x;
	int    TraceSize;
	char** Messages;
	std::stringstream msg;
	msg << _("Received sigal: ") << strsignal(sig)
			<< " (" << si->si_addr << ")" << std::endl;
#if __WORDSIZE == 64 // os type
	ErrorAddr = (void*)((ucontext_t*)ptr)->uc_mcontext.gregs[REG_RIP];
#else
	ErrorAddr = (void*)((ucontext_t*)ptr)->uc_mcontext.gregs[REG_EIP];
#endif
	TraceSize = backtrace(Trace, 16);
	Trace[1] = ErrorAddr;
	Messages = backtrace_symbols(Trace, TraceSize);
	if (Messages)
	{
		const char intend[] = "  ";
		msg << intend << _("== Backtrace ==") << std::endl;
		for (x = 1; x < TraceSize; x++)
			msg << intend << Messages[x] << std::endl;
		msg << intend << _("== End Backtrace ==");
		ELOG << msg.str();
		free(Messages);
	}

	ELOG << _("Exception occur. Hard stopping.");

	// TODO: It will be best to legally stop here, or, at least give
	// inheritances chance to do some work: handle closing,
	// destructing or smth...

	exit(2); // need restart status
}

void ProcessManagerBase::loop()
{
	alarm(1);
	for (;;)
	{
		int               signo;
		sigwait(&sigset_, &signo);
		if (signo == SIGALRM)
		{
			//VLOG << "Signal waiting loop iteration.";
			if (state_ == STATE_NULL)
				break;
			alarm(1);
			continue;
		}
		else if (signo == SIGUSR1)
		{
			// TODO: config renew
		}
		else
		{
			VLOG << _("Received signal: ") << strsignal(signo);
			Stop();
			break;
		}
	}
}

void*
ProcessManagerBase::start_loop(void* process_manager)
{
	if(!process_manager)
		return NULL;
	ProcessManagerBase *pm = (ProcessManagerBase*)process_manager;
	pm->loop();
	return NULL;
}

void
ProcessManagerBase::setupSignals(sigset_t& sigset)
{
	struct sigaction sigact;
	sigact.sa_flags = SA_SIGINFO;
	sigact.sa_sigaction = ProcessManagerBase::signalError;
	sigemptyset(&sigact.sa_mask);
	sigaction(SIGFPE, &sigact, 0);
	sigaction(SIGILL, &sigact, 0);
	sigaction(SIGSEGV, &sigact, 0);
	sigaction(SIGBUS, &sigact, 0);

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGQUIT);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void
ProcessManagerBase::Dispatch()
{
	if(state_ == STATE_RUNNING)
		return;
	else if(state_ == STATE_RUNNING_D)
		return;
	else if(state_ == STATE_NULL)
	{
		setupSignals(sigset_);
		VLOG << _("Initializing");
		if(!doStart())
		{
			ELOG << _("Initializing process failed ");
			return;
		}
		{
			std::lock_guard<std::mutex> lock(state_mtx_);
			state_ = STATE_RUNNING_D;
		}
		VLOG << _("Staring main loop");
		thread_.reset(new std::thread(start_loop, this));
	}
}

void
ProcessManagerBase::Loop()
{
	if(state_ == STATE_RUNNING)
		return;
	else if(state_ == STATE_RUNNING_D)
		return;
	else if(state_ == STATE_NULL)
	{
		setupSignals(sigset_);
		VLOG << _("Initializing");
		if(!doStart())
		{
			ELOG << _("Initializing process failed ");
			return;
		}
		{
			std::lock_guard<std::mutex> lock(state_mtx_);
			state_ = STATE_RUNNING;
		}
		VLOG << _("Starting main loop");
		loop();
	}
}

void
ProcessManagerBase::Stop()
{
	if(state_ == STATE_NULL)
		return;
	bool need_join = false;
	if(state_ == STATE_RUNNING_D)
		need_join = true;
	if(state_ == STATE_RUNNING || state_ == STATE_RUNNING_D)
	{
		{
			std::lock_guard<std::mutex> lock(state_mtx_);
			state_ = STATE_NULL;
		}
		VLOG << _("Cleaning");
		if(!doStop())
			ELOG << _("Cleaning process failed");
	}
	VLOG << _("Stopping");
	if(thread_)
		thread_->join();
}

} // namespace

