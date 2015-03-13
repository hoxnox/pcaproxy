/**@author $username$ <$usermail$>
 * @date $date$*/

#ifndef __PCAPROXY_UTILS_HPP__
#define __PCAPROXY_UTILS_HPP__

#include <utils/NxSocket.h>
#include <utils/MkDir.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <locale>

namespace pcaproxy {

inline size_t
file_size()
{
}

template <class OutputIterator>
void split(const std::string& str, OutputIterator out,
           const std::string& delimiter = " ", bool trimEmpty = false)
{
	ssize_t pos, lastPos = 0;
	while(true)
	{
		pos = str.find_first_of(delimiter, lastPos);
		if(pos == std::string::npos)
		{
			pos = str.length();
			if(pos != lastPos || !trimEmpty)
				*out++ = std::string(str.data()+lastPos, (ssize_t)pos-lastPos);
			break;
		}
		else
		{
			if(pos != lastPos || !trimEmpty)
				*out++ = std::string(str.data()+lastPos, (ssize_t)pos-lastPos);
		}
		lastPos = pos + 1;
	}
}

static inline std::string
tolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), ::tolower);
	return s;
}

static inline std::string
ltrim(std::string s)
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

static inline std::string
rtrim(std::string s)
{
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

static inline std::string
trim(std::string s)
{
	return ltrim(rtrim(s));
}

/**@brief Create directories (recursive)
 * @note will be created directories before
 * the last occurring of '/'. For example: "test/my/dirs" will create
 * "test" and "my", but "test/my/dirs/" creates all of them.*/
inline bool check_create_dir(std::string path)
{
	size_t tmp = path.find_last_of('/');
	if(tmp == std::string::npos)
		return true;
	path = path.substr(0, tmp);

	if (mkpath(path.c_str(),
			S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)
	{
		return false;
	}
	return true;
}

inline char
hex2char(unsigned char n)
{
	if(0 <= n && n <= 9)
		return n + 48;
	if(0xA <= n && n <= 0xF)
		return n - 0xA + 65;
	return '?';
}

inline std::string
byte2str(const char * bytes, const size_t bytesz)
{
	std::string result;
	if (bytes == NULL || bytesz == 0)
		return result;
	for(size_t i = 0; i < bytesz; ++i)
	{
		result += hex2char((((unsigned char)bytes[i])/0x10)%0x10);
		result += hex2char(((unsigned char)bytes[i])%0x10);
	}
	return result;
}

inline std::string
byte2str(std::vector<char>& bytes)
{
	return byte2str((const char*)&bytes[0], bytes.size());
}

inline std::string
inet_ntos(uint32_t num)
{
	char buf[50];
	memset(buf, 0, sizeof(buf));
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = num;
	if (inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf) - 1) == NULL)
		return "";
	return std::string(buf);
}

} // namespace

#endif // __PCAPROXY_UTILS_HPP__

