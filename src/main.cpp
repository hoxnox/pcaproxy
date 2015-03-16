/**@author $username$ <$usermail$>
 * @date $date$ */

#include <Config.hpp>
#include <ProcessManager.hpp>
#include <Logger.hpp>
#include <utils/NxSocket.h>
#include <gettext.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>

using namespace pcaproxy;

int
main(int argc, char* argv[])
{
	Config::Ptr cfg = Config::GetInstance();
	cfg->SetDefaults();
	cfg->LoadFile(Config::DEFAULT_CONFIG_FILE, true);
	cfg->LoadFile(Config::DEFAULT_USER_CONFIG_FILE, true);

	int rs = cfg->ParseArgs(argc, argv);
	if(rs != 0)
		return 0;

	cfg->InitLogStream(Logger::ilog, 'I');
	cfg->InitLogStream(Logger::elog, 'E');

	bool forked = false;
#ifndef WIN32
	if(cfg->Fork())
	{
		pid_t fork_pid = fork();
		if(fork_pid > 0)
		{
			VLOG << _("Forked to ") << fork_pid << std::endl;
			return 0;
		}
		else if(fork_pid == 0)
		{
			forked = true;
			setsid();
			int rs = chdir("/");
			if(rs == -1)
				VLOG << _("chdir error.")
					<< _(" Message: ") << strerror(errno);
		}
		else
		{
			ELOG << _("Error forking proccess.") << " "
				<< _("Message") << ": " << strerror(errno);
		}
	}
#endif

	if (cfg->Verbose())
		Logger::verbose = true;
	VLOG << cfg->GetOptions();

	PCAParser::Ptr pcaparser = PCAParser::GetInstance();
	pcaparser->Parse(cfg->Filename(), cfg->ParseDir());
	SetNonBlock(0); // stdin
	ProcessManager pm;
	pm.Loop();

	return 0;
}

