/* @author Merder Kim <hoxnox@gmail.com>
 * @date 20121215 22:11:34*/

#include "LogStream.hpp"
#include <string.h>
#include <gettext.h>
#include <iostream>
#include <cassert>
#include <sys/types.h>
#include <unistd.h>
#ifdef WIN32
#include <process.h>
#endif

#ifndef _THREAD_SAFE
#define _THREAD_SAFE
#endif

namespace pcaproxy {

/**@class LogStream
 * @brief Used to send log messages to file, or to UDP stream (or both, if copy is set)
 *
 * To simplify logging, we use a trick with std::stringstream. So it is not a good idea to use this
 * class directly. See logging.hpp instead. But, if you wish, here is example:
 * @code
 * LogStream log;
 * log < log._stream() << "This is logging string  number " << 1;
 * @endcode
 * Other usage can cause undefined behaviour, since "<<" locks mutex and "<" unlocks for thread
 * safety. Don't use "<" with std::ostream - it is realy bad idea!
 *
 * Logger type is defined by type argument in constructors. */

/**@var LogStream::default_fname_
 * @brief Default filename, used to save log messages*/
const char               LogStream::default_fname_[] = "logstream.log";

inline char hex2char(unsigned char n)
{
	if(0 <= n && n <= 9)
		return n + 48;
	if(0xA <= n && n <= 0xF)
		return n - 0xA + 65;
	return '?';
}

inline void pid2str(char * src, const uint32_t num)
{
	if (src == NULL)
		return;

	memset(src, 0, 9);
	sprintf(src, "%08X", num);
	src[8] = 0;
	/*
	uint32_t num_n = htonl(num);

	src[0] += hex2char((((unsigned char)(num_n/0x1000000))/0x10)%0x10);
	src[1] += hex2char(((unsigned char)(num_n/0x1000000))%0x10);

	src[2] += hex2char((((unsigned char)((num_n/0x10000)%0x100))/0x10)%0x10);
	src[3] += hex2char(((unsigned char)((num_n/0x10000)%0x100))%0x10);
	
	src[4] += hex2char((((unsigned char)((num_n/0x100)%0x100))/0x10)%0x10);
	src[5] += hex2char(((unsigned char)((num_n/0x100)%0x100))%0x10);
	
	src[6] += hex2char((((unsigned char)(num_n%0x100))/0x10)%0x10);
	src[7] += hex2char(((unsigned char)(num_n%0x100))%0x10);
	
	src[sizeof(uint32_t) + 1] = 0;*/
}

/**@brief Default constructor (UDP-based logger with the default address)
 * @param - logger type*/
LogStream::LogStream(const char type /*= 'I'*/) throw (std::exception)
	: type_(type)
	, truncmtu_(false)
	, MTU_SAFE_PAYLOAD_SIZE_(512)
	, stream_(NULL)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_init(&mtx_, NULL);
	pthread_mutex_init(&mtx_r_, NULL);
	#endif // _THREAD_SAFE
	SOCK_INIT();
	init_default(addr_);
	sock_ = socket(addr_.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (!IS_VALID_SOCK(sock_) || SetNonBlock(sock_) < 0
		|| SetReusable(sock_) < 0 || SetBroadcast(sock_) < 0)
	{
		throw std::runtime_error(
				std::string(_("error opening socket"))
					+ " \"" + strerror(GET_LAST_SOCK_ERROR()) + "\"");
	}
}

/**@brief Construct LogStream with socket logging
 * @throw std::runtime_error on error socket opening*/
LogStream::LogStream(struct sockaddr *addr, const char type /*= 'I'*/) throw (std::exception)
	: type_(type)
	, truncmtu_(false)
	, MTU_SAFE_PAYLOAD_SIZE_(512)
	, stream_(NULL)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_init(&mtx_, NULL);
	pthread_mutex_init(&mtx_r_, NULL);
	#endif // _THREAD_SAFE
	if(addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		init_default(addr_);
	else
		CopySockaddrToStorage(addr, &addr_);
	sock_ = socket(addr_.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if(!IS_VALID_SOCK(sock_) || SetNonBlock(sock_) < 0
		|| SetReusable(sock_) < 0 || SetBroadcast(sock_) < 0)
	{
		throw std::runtime_error(
				std::string(_("error opening socket"))
					+ " \"" + strerror(GET_LAST_SOCK_ERROR()) + "\"");
	}
}


/**@brief Construct LogStream with file logging
 * @throw std::runtime_error on error file opening*/
LogStream::LogStream(std::ostream& ostrm, const char type /*= 'I'*/) throw (std::exception)
	: sock_(INVALID_SOCKET)
	, type_(type)
	, truncmtu_(false)
	, MTU_SAFE_PAYLOAD_SIZE_(512)
	, stream_(NULL)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_init(&mtx_, NULL);
	pthread_mutex_init(&mtx_r_, NULL);
	#endif // _THREAD_SAFE
	stream_ = &ostrm;
}
/**@brief Construct LogStream with file logging
 * @throw std::runtime_error on error file opening*/
LogStream::LogStream(const std::string filename, const char type /*= 'I'*/) throw (std::exception)
	: sock_(INVALID_SOCKET)
	, type_(type)
	, truncmtu_(false)
	, MTU_SAFE_PAYLOAD_SIZE_(512)
	, stream_(NULL)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_init(&mtx_, NULL);
	pthread_mutex_init(&mtx_r_, NULL);
	#endif // _THREAD_SAFE
	file_.open(filename.c_str(), std::fstream::out | std::fstream::binary);
	if(!file_.is_open())
	{
		throw std::runtime_error(
				std::string(_("error opening file")) + " \"" + filename + "\"");
	}
}

/**@brief Redirect log stream to another address
 * @return 0 on success, negative on error*/
int LogStream::redirect(const sockaddr *addr, bool copy /*= false*/)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_lock(&mtx_r_);
	#endif // _THREAD_SAFE
	if(addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		init_default(*(struct sockaddr_storage*)addr);
	else
		CopySockaddrToStorage(addr, &addr_);
	if(!copy)
	{
		if(file_.is_open())
			file_.close();
		stream_ = NULL;
	}
	SOCK_INIT();
	sock_ = socket(addr_.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if(!IS_VALID_SOCK(sock_) || SetNonBlock(sock_) < 0
		|| SetReusable(sock_) < 0 || SetBroadcast(sock_) < 0)
	{
		throw std::runtime_error(
				std::string(_("error opening socket"))
					+ " \"" + strerror(GET_LAST_SOCK_ERROR()) + "\"");
	}
	#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mtx_r_);
	#endif // _THREAD_SAFE
	return 0;
}

/**@brief Redirect log stream to file
 * @return 0 on success, negative on error*/
int LogStream::redirect(const std::string filename, bool copy /*= false*/)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_lock(&mtx_r_);
	#endif // _THREAD_SAFE
	if(file_.is_open())
		file_.close();
	file_.open(filename.c_str(), std::fstream::out | std::fstream::binary);
	bool rs = file_.is_open();
	if(!copy)
	{
		//close(sock_);
		sock_ = INVALID_SOCKET;
		stream_ = NULL;
	}
	#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mtx_r_);
	#endif // _THREAD_SAFE
	return rs == true ? 0 : -1;
}

/**@brief Redirect log stream to some EXISTING stream
 * @return 0 on success, negative on error
 *
 * @warning String must exist. LogStream doesn't own the stream! Be
 * careful. Normal use case - redirect to std::out, std::log or
 * std::err.*/
int
LogStream::redirect(std::ostream& ostrm, bool copy/* = false*/)
{
	#ifdef _THREAD_SAFE
	pthread_mutex_lock(&mtx_r_);
	#endif // _THREAD_SAFE
	stream_ = &ostrm;
	if(!copy)
	{
		close(sock_);
		sock_ = INVALID_SOCKET;
		if(file_.is_open())
			file_.close();
	}
	bool rs = stream_->good();
	#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mtx_r_);
	#endif // _THREAD_SAFE
	return rs == true ? 0 : -1;
}

LogStream::~LogStream()
{
	#ifdef _THREAD_SAFE
	pthread_mutex_lock(&mtx_);
	pthread_mutex_lock(&mtx_r_);
	#endif // _THREAD_SAFE
	flush_unsafe();
	if(file_.is_open())
		file_.close();
	/*
	if(IS_VALID_SOCK(sock_))
		close(sock_);*/
	#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mtx_);
	pthread_mutex_destroy(&mtx_);
	pthread_mutex_unlock(&mtx_r_);
	pthread_mutex_destroy(&mtx_r_);
	#endif // _THREAD_SAFE
}

/**@brief This function is tricky and used with operator<.
 * @warning It's bad idea to use this function directly.
 *
 * This function is used to simplify macro definition for "stream logging", like this:
 * @code
 * 	LOG << "Some text" << 21334 << 5.332 << "Some text" << ' ';
 * @endcode
 * This function wrapped with the `operator<` together, so we can define macro like this:
 * @code
 * LogStream log;
 * #define LOG log < log._stream()
 * LOG << "blah blah blah " << 123 << " and numbers";
 * @endcode*/
std::stringstream& LogStream::_stream()
{
	#ifdef _THREAD_SAFE
	pthread_mutex_lock(&mtx_);
	#endif // _THREAD_SAFE
	std::stringstream *ss = new std::stringstream;
	Msg msg = {ss, time(NULL)};
	ss_.push_back(msg);
	return *ss;
}

/**@brief Used to flush data, written to stringstream, generated by _stream() function
 * @warning It's bad idea to use this function directly! It must be paired with _stream(), 
 * see _stream() for details*/
LogStream& LogStream::operator< (std::ostream& ss) throw (std::exception)
{
	flush_unsafe();
	#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mtx_);
	#endif // _THREAD_SAFE
	return *this;
}

/**@brief Thread unsafe flush message to stream or file.*/
void LogStream::flush_unsafe() throw (std::exception)
{
	if(ss_.empty())
		return;
	if(!file_.is_open() && !IS_VALID_SOCK(sock_) && stream_ == NULL)
	{
		#ifdef _THREAD_SAFE
		pthread_mutex_unlock(&mtx_);
		#endif // _THREAD_SAFE
		throw std::runtime_error("Logger error: file, stream and socket are illegal");
	}
	for(std::vector<Msg>::iterator i = ss_.begin();
			i != ss_.end(); ++i)
	{
		if(i->sstr != NULL)
		{
			if (file_.is_open())
				print_log(*i, file_);
			if (IS_VALID_SOCK(sock_))
				send_log(*i);
			if (stream_ != NULL)
				print_log(*i, *stream_);
			delete i->sstr;
			i->sstr = NULL;
		}
	}
	ss_.clear();
}


/**@brief create string representation of message
 *
 * Format:
 * 	+---+---+---+...+---+---+---+---+---+---+---+---+---+...+---+
 * 	|x5B|TYP|DTTM_STR   |x50|PID_HEX        |x5D|x20|DAT        |
 * 	+---+---+---+...+---+---+---+---+---+---+---+---+---+...+---+
 *where
 *
 *- TYP & DAT - message type and data
 *- DTTM_STR - string date representation (YYYYMMDDTHHMMS)
 *  for example 20121214T125511 - "2012 Dec 14 12:55:11"
 *
 *x5B, x5D & x20 - constants '[', ']' & ' ' respectively
 *
 *### exmaple:
 *
 * 	[E20121214T125511P00001A21] Hello, world!*/
std::string LogStream::format_str_msg(const Msg msg) const
{
	char pid_[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint32_t upid_;
#	ifdef WIN32
	upid_ = (uint32_t)_getpid();
#	else
	upid_ = (uint32_t)getpid();
#	endif
	pid2str(pid_, upid_);
	std::stringstream ss;
	char buf[16];
	buf[15] = '\0';
	strftime(buf, 16, "%Y%m%dT%H%M%S", localtime(&msg.time));
	ss << "[" << type_ << buf << 'P' << pid_ << "] " << msg.sstr->str() << std::endl;
	return ss.str();
}

/**@brief prints message in the file*/
void LogStream::print_log(const Msg msg, std::ostream& strm)
{
	if(!strm.good())
	{
		std::cerr << _("Error saving log message to file.")
			<< _(" Message:") << format_str_msg(msg);
	}
	else
	{
		strm << format_str_msg(msg);
	}
}

// VS has min diclarations
#ifndef min
inline int min(int a, int b)
{
	return a < b ? a : b;
}
#endif

/**@brief send message as UDP packet. Message, longer than 60000 bytes,
 * will be truncated. Note that long messages (longer, than MTU) can cause
 * troubles on the receiving side.*/
void LogStream::send_log(const Msg msg)
{
	char pid_[9];
	uint32_t upid_;
#	ifdef WIN32
	upid_ = (uint32_t)_getpid();
#	else
	upid_ = (uint32_t)getpid();
#	endif
	pid2str(pid_, upid_);
	int hdrln = 1 + 2 + 1 + 4 + 4 + 1;
	std::string str(msg.sstr->str());
	size_t max_payload_size = (unsigned)60000 - hdrln;
	if(truncmtu_)
		max_payload_size = MTU_SAFE_PAYLOAD_SIZE_ - hdrln;
	int msgln = min(max_payload_size, str.length());
	int bufsz = msgln + hdrln;
	char * buf = new char[bufsz];
	buf[0] = 0x01;
	*(uint16_t*)&buf[1] = htons(msgln);
	buf[3] = type_;
	*(uint32_t*)&buf[4] = htonl(msg.time);
	*(uint32_t*)&buf[8] = htonl(upid_);
	buf[12] = 0x02;
	memcpy(&buf[13], str.data(), msgln);
	if(IS_VALID_SOCK(sock_))
	{
		int rs = sendto(sock_, buf, bufsz, 0, (struct sockaddr*)&addr_, sizeof(struct sockaddr_in));
		if(rs <= 0)
			std::cerr << _("Error sending log message.")
				<< " Error: \"" << strerror(GET_LAST_SOCK_ERROR()) << "\""
				<< " Message: " << format_str_msg(msg);
	}
	else
	{
		std::cerr << _("Error sending log message. Invalid socket.")
			<< " Message:" << format_str_msg(msg);
	}
	delete [] buf;
}

} // namespace

