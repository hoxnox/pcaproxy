/**@author Merder Kim <hoxnox@gmail.com>
 * @date 20140507 10:45:29 */

#include "Config.hpp"
#include <getopt.h>
#include <Logger.hpp>
#include <gettext.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <pcaproxy_config.h>
#include <stdlib.h>
#include <cctype>
#include <cstring>
#include <errno.h>

namespace pcaproxy {

const std::string Config::DEFAULT_CONFIG_FILE = "/etc/pcaproxy.conf";
const std::string Config::DEFAULT_USER_CONFIG_FILE = "~/.config/pcaproxy/pcaproxy.conf";
Config::Ptr Config::instance_;

Config::Config()
{
	SetDefaults();
}

Config::~Config()
{}

void
Config::SetDefaults()
{
	verbose_          = false;
	fork_             = false;
	logging_          = "std";
	filename_         = "";
	dontclean_        = false;
	parsedir_         = "/tmp/pcaproxy";
	bind_addr_        = "127.0.0.1:48080";
	backlog_          = 100;
	tick_             = {1, 0};
}

inline std::string
expand_path(const std::string path)
{
	std::string result;
	char * tmp = new char[4096];
	if(tmp != NULL)
	{
		if(realpath(path.c_str(), tmp) == NULL)
		{
			std::cerr << _("Config: Error resolving path: ")
			          << "\"" << path << "\""
			          << _(" Message: ") << strerror(errno)
			          << std::endl;
			return result;
		}
		result.assign(tmp);
		delete [] tmp;
	}
	return result;
}

void Config::InitLogStream(LogStream& log, const char type)
{
	switch(type)
	{
		case 'I': log.redirect(std::clog); break;
		case 'E': log.redirect(std::cerr); break;
	}
	return;
}

int
Config::ParseArgs(int argc, char* argv[])
{
	std::string opt_l, opt_c, opt_b, opt_p;
	bool opt_V = false, opt_F = false, opt_s = false;

	const char *sopts = "VvFhsl:c:b:";

	const struct option lopts[] = {
		{ "bind",              required_argument, NULL, 'b' },
		{ "verbose",           no_argument,       NULL, 'V' },
		{ "version",           no_argument,       NULL, 'v' },
		{ "logging",           required_argument, NULL, 'l' },
		{ "parsedir",          required_argument, NULL, 'p' },
		{ "dontclean",         no_argument,       NULL, 's' },
		{ "config",            required_argument, NULL, 'c' },
		{ "fork",              no_argument,       NULL, 'F' },

		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, '\0'}
	};

	int i, opt = 0;
	opt = getopt_long(argc, argv, sopts, lopts, &i);
	while (opt != -1)
	{
		switch (opt)
		{
			case 'V': opt_V = true; break;
			case 'b': opt_b = optarg; break;
			case 'l': opt_l = optarg; break;
			case 'c': opt_c = optarg; break;
			case 'p': opt_p = optarg; break;
			case 's': opt_s = true; break;
			case 'F': opt_F = true; break;
			case 'h': printHelp(); return 1;
			case 'v': printVersion(); return 1;
			case  -1: return -1;
			case '?': return -1;
		}
		opt = getopt_long( argc, argv, sopts, lopts, &i );
	}
	if (!opt_c.empty()) LoadFile(opt_c);
	if (opt_V) verbose_ = true;
	if (opt_F) fork_    = true;
	if (opt_s) dontclean_ = true;
	if (!opt_p.empty()) parsedir_ = expand_path(opt_p);
	if (!opt_b.empty()) bind_addr_ = opt_b;
	if (!opt_l.empty()) logging_   = opt_l;

	if (optind < argc)
		filename_ = expand_path(argv[optind++]);
	else
		printInfo();

	if (filename_.empty())
		return -1;
	return 0;
}

template<class T>
inline std::stringstream&
append_opt(std::stringstream& ss, std::string varname, T val, bool endl = true)
{
	ss << std::setw(2) << "" << varname << " = " << std::boolalpha << val;
	if(endl)
		ss << std::endl;
	return ss;
}

inline std::vector<std::string>
split(std::string str, size_t len)
{
	std::vector<std::string> rs;
	if (str.empty() || len < 15)
		return rs;
	while(str.length() > len)
	{
		size_t splitpos = len;
		while (str[splitpos] != ' ' && splitpos > 0)
			--splitpos;
		if (splitpos == 0)
		{
			splitpos = len;
			while(str[splitpos] != ' ' && splitpos < str.length())
				++splitpos;
		}
		rs.push_back(str.substr(0, splitpos));
		str = str.substr(splitpos + 1, str.length() - splitpos);
	}
	rs.push_back(str);
	return rs;

}

template<class T>
inline std::stringstream&
append_hlp(std::stringstream& ss, std::string opt_short, std::string opt_long,
		T default_val, std::string desc)
{
	size_t totaln = 80;
	size_t optln = 23;
	size_t defln = 19;
	size_t dscln = totaln - optln - defln;
	std::stringstream opt;
	std::stringstream def;
	std::stringstream dsc;
	std::stringstream defempty;

	std::vector<std::string> desc_pieces = split(desc, dscln);
	std::vector<std::string>::iterator i = desc_pieces.begin();

	opt << "-" << opt_short << "(--" << opt_long << ")";
	def << std::boolalpha << " [" << default_val << "] ";
	defempty << std::boolalpha << " [" << "] ";
	ss << std::left << std::setfill(' ')
	   << std::setw(optln) << opt.str()
	   << std::setw(defln) << (def.str() == defempty.str() ? "" : def.str())
	   << *i++ << std::endl;
	for(; i != desc_pieces.end(); ++i)
		ss << std::setw(optln + defln) << "" << *i << std::endl;
	return ss;
}

std::string
Config::GetOptions() const
{
	std::stringstream ss;
	ss << "Options" << std::endl;
	append_opt(ss, "Verbose"        , Verbose());
	append_opt(ss, "BindAddr"       , BindAddr());
	append_opt(ss, "Fork"           , Fork());
	append_opt(ss, "ParseDir"       , ParseDir());
	append_opt(ss, "DontClean"      , DontClean());
	append_opt(ss, "Logging"        , Logging());
	return ss.str();
}

void
Config::printVersion() const
{
	std::cout << pcaproxy_VERSION_MAJOR << "."
	          << pcaproxy_VERSION_MINOR << "."
	          << pcaproxy_VERSION_PATCH << std::endl;
}

void
Config::printInfo() const
{
	std::cout << _("PCAProxy (ver. ")
	          << pcaproxy_VERSION_MAJOR << "."
	          << pcaproxy_VERSION_MINOR << "."
	          << pcaproxy_VERSION_PATCH << ")" << std::endl
	          << _("Usage: pcaproxy [options] <pcapfile>") << std::endl;
}

void
Config::printHelp() const
{
	printInfo();
	std::stringstream ss;
	ss << std::endl << _("Options:") << std::endl;
	append_hlp(ss, "c", "config"            , ""                 , _("load config from file"));
	append_hlp(ss, "b", "bind-addr"         , BindAddr()         , _("bind address"));
	append_hlp(ss, "V", "verbose"           , Verbose()          , _("make a lot of noise"));
	append_hlp(ss, "F", "fork"              , Fork()             , _("fork to independent process"));
	append_hlp(ss, "p", "parsedir"          , ParseDir()         , _("directory to save parsed data"));
	append_hlp(ss, "s", "donclean"          , DontClean()        , _("do not clean parse directory on exit"));
	append_hlp(ss, "l", "logging"           , Logging()          , _("logging destination"));
	append_hlp(ss, "v", "version"           , ""                 , _("print version"));
	append_hlp(ss, "h", "help"              , ""                 , _("print this message"));
	std::cout << std::boolalpha << ss.str() << std::endl;
}

inline std::string
trim(std::string str)
{
	size_t begin = 0, end = str.length() - 1;
	while (begin < str.length() && isspace(str[begin]))
		++begin;
	while (end != 0 && isspace(str[end]))
		--end;
	if(end - begin > 0)
		return str.substr(begin, end - begin + 1);
	else
		return std::string();
}

inline std::string
lower(std::string str)
{
	std::string result;
	for(size_t i = 0; i < str.length(); ++i)
		result += std::tolower(str[i]);
	return result;
}

inline bool
str2bool(std::string str)
{
	str = lower(str);
	if(str == "0" || str == "no" || str == "false")
		return false;
	else
		return true;
}

bool
Config::LoadFile(const std::string file, bool silent /* = false*/)
{
	std::ifstream cfg_file(file.c_str());
	if (!cfg_file.is_open())
	{
		if (!silent)
		{
			std::cerr << _("Error config file loading.")
			          << _(" Path: ") << file
			          << _(" Message: ") << strerror(errno)
			          << std::endl;
		}
		return false;
	}
	size_t line_no = 0;
	while(!cfg_file.eof())
	{
		std::string line;
		getline(cfg_file, line);
		++line_no;
		size_t comment = line.find('#');
		std::string ln;
		if(comment != std::string::npos)
			ln = trim(line.substr(0, comment));
		else
			ln = trim(line);
		if(ln.empty())
			continue;
		size_t divisor = ln.find('=');
		if(divisor == std::string::npos)
		{
			std::cerr << _("Config error in line") 
			          << " " << line_no << ": "
			          << "No '=' found" << std::endl;
			continue;
		}
		std::string name  = lower(trim(ln.substr(0, divisor)));
		std::string value = trim(ln.substr(
					divisor + 1, ln.length() - divisor));

		if     (name == "verbose"            ) verbose_          = str2bool(value);
		else if(name == "bindaddr"           ) bind_addr_        = value;
		else if(name == "logging"            ) logging_          = value;
		else if(name == "parsedir"           ) parsedir_         = expand_path(value);
		else if(name == "donclean"           ) dontclean_        = str2bool(value);
		else if(name == "fork"               ) fork_             = str2bool(value);
		else
		{
			std::cerr << _("Config error in line") << " " << line_no << ": "
				<< "Unsupported option." << std::endl;
		}
	}
	return true;
}

} // namespace

