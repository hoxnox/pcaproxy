/**@author Merder Kim <hoxnox@gmail.com>
 * @date 20140507 10:45:29 */

#ifndef __CONFIG_HPP__
#define __CONFIG_HPP__

#include <string>
#include <memory>
#include <utils/LogStream.hpp>

namespace pcaproxy {

class Config
{
public:
	typedef std::shared_ptr<Config> Ptr;
	Config();
	~Config();
	static Ptr  GetInstance();
	bool        LoadFile(const std::string file, bool silent = false);
	int         ParseArgs(int argc, char* argv[]);
	void        SetDefaults();
	std::string GetOptions() const;
	void        InitLogStream(LogStream& log, const char type);

	bool        Verbose()           const { return verbose_;          }
	bool        Fork()              const { return fork_;             }
	std::string Logging()           const { return logging_;          }

	static const std::string DEFAULT_CONFIG_FILE;
	static const std::string DEFAULT_USER_CONFIG_FILE;
private:
	void printHelp() const;
	void printVersion() const;
	void printInfo() const;

	bool                    verbose_;
	bool                    fork_;
	std::string             logging_;
	static Ptr              instance_;
	struct sockaddr_storage iaddr_;
	struct sockaddr_storage eaddr_;
};

////////////////////////////////////////////////////////////////////////
// inline

inline Config::Ptr
Config::GetInstance()
{
	if (!instance_)
		instance_.reset(new Config);
	return instance_;
}

} // namespace

#endif // __CONFIG_HPP__

