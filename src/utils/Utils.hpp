/**@author hoxnox <hoxnox@gmail.com>
 * @date 20150316 16:36:18*/

#ifndef __PCAPROXY_UTILS_HPP__
#define __PCAPROXY_UTILS_HPP__

#include <utils/NxSocket.h>
#include <utils/MkDir.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <locale>
#include <fstream>
#include <dirent.h>

namespace pcaproxy {

template<class OutputIterator> bool
read_file(std::string fname, OutputIterator out)
{
	std::ifstream ifile(fname.c_str(), std::ios::binary | std::ios::in);
	if (!ifile.good())
		return false;
	std::istreambuf_iterator<char> reader(ifile.rdbuf());
	while (reader != std::istreambuf_iterator<char>())
		*out++ = *reader++;
	return true;
}

template <class OutputIterator> void
split(const std::string& str, OutputIterator out,
      const std::string delimiter = " ", bool trimEmpty = false)
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

template<class OutputIterator> bool
wheel_dir(std::string dirname, OutputIterator out, const std::string suffix)
{
	std::vector<std::string> rsp_fnames;
	DIR *dir = opendir(dirname.c_str());
	if (dir == NULL)
		return false;
	struct dirent *ent;
	for (dirent *ent = readdir(dir); ent != NULL; ent = readdir(dir))
	{
		std::string fname(dirname + "/" + ent->d_name);
		size_t fnamelen = strlen(ent->d_name);
		if (fnamelen < suffix.length())
			continue;
		size_t pos = fnamelen - suffix.length();
		for (size_t i = 0; i < suffix.length(); ++i)
			if (suffix[i] != ent->d_name[pos + i])
				continue;
		*out++ = fname;
	}
	closedir(dir);
	return true;
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

