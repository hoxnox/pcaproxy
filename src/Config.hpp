/**@author Merder Kim <hoxnox@gmail.com>
 * @date 20140507 10:45:29 */

#ifndef __CONFIG_HPP__
#define __CONFIG_HPP__

#include <string>
#include <memory>
#include <utils/LogStream.hpp>
#include <utils/NxSocket.h>

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

	bool           Verbose()    const { return verbose_;          }
	bool           Fork()       const { return fork_;             }
	std::string    Logging()    const { return logging_;          }
	std::string    BindAddr()   const { return bind_addr_;        }
	std::string    Filename()   const { return filename_;         }
	std::string    ParseDir()   const { return parsedir_;         }
	bool           DontClean()  const { return dontclean_;        }
	int            Backlog()    const { return backlog_;          }
	struct timeval Tick()       const { return tick_;             }

	static const std::string DEFAULT_CONFIG_FILE;
	static const std::string DEFAULT_USER_CONFIG_FILE;
	static struct sockaddr_storage Str2Inaddr(std::string str);
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
	std::string             filename_;
	std::string             bind_addr_;
	std::string             parsedir_;
	bool                    dontclean_;
	int                     backlog_;
	struct timeval          tick_;
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

inline struct sockaddr_storage
Config::Str2Inaddr(std::string str)
{
	struct sockaddr_storage addr;
	std::uninitialized_fill((char*)&addr, (char*)&addr + sizeof(addr), 0);
	addr.ss_family = AF_INET;
	size_t colon = str.find(':');
	if (colon == std::string::npos)
	{
		((struct sockaddr_in*)&addr)->sin_port = 0xcccc;
		colon = str.length();
	}
	else
	{
		((struct sockaddr_in*)&addr)->sin_port = htons(atoi(
			str.substr(colon+1, str.length() - colon - 1).c_str()));
	}
	char tmp[50];
	std::uninitialized_fill(tmp, tmp + sizeof(tmp), 0);
	if (inet_pton(AF_INET, str.substr(0, colon).c_str(), 
			GetAddr((struct sockaddr*)&addr)) != 1)
	{
		std::uninitialized_fill((char*)&addr, (char*)&addr + sizeof(addr), 0);
	}
	return addr;
}

} // namespace

#endif // __CONFIG_HPP__

