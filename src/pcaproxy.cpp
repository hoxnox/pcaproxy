/**@author $username$ <$usermail$>
 * @date $date$ */

#include <Config.hpp>
#include <ProcessManager.hpp>
#include <Logger.hpp>
#include <utils/NxSocket.h>
#include <gettext.h>

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
	{
		if(rs < 0)
			ELOG << _("Error parsing arguments.");
		return 0;
	}

	cfg->InitLogStream(Logger::ilog, 'I');
	cfg->InitLogStream(Logger::ilog, 'E');

	if (cfg->Verbose())
		Logger::verbose = true;
	VLOG << cfg->GetOptions();

	SetNonBlock(0); // stdin
	ProcessManager pm;
	pm.Loop();

	return 0;
}

