/* @author Merder Kim <hoxnox@gmail.com>
 * @date 20121215 22:11:34*/

#ifndef __LOGSTREAM_HPP__
#define __LOGSTREAM_HPP__

#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <ctime>
#include <mutex>

#include <utils/NxSocket.h>

namespace pcaproxy {

class LogStream
{
	public:

		/**@name ctor/dtor
		 * @{*/
		LogStream(const char type = 'I')
			throw (std::exception);
		LogStream(struct sockaddr *addr, const char type = 'I')
			throw (std::exception);
		LogStream(const std::string filename, const char type = 'I')
			throw (std::exception);
		LogStream(std::ostream& ostrm, const char type = 'I')
			throw (std::exception);
		~LogStream();
		/**@}*/

		/**@name stream redirectors
		 * @{*/
		int redirect(const sockaddr *addr, bool copy = false);
		int redirect(const std::string filename, bool copy = false);
		int redirect(std::ostream& strm, bool copy = false);
		/**@}*/

		/**@name options*/
		/**@{*/
		void SetTruncateMTU(const bool tr) {truncmtu_ = tr;}
		/**@}*/

		std::stringstream& _stream();
		LogStream& operator< (std::ostream& ss) throw (std::exception);

	private:
		typedef struct
		{
			std::stringstream * sstr;
			time_t time;
		} Msg;
		void flush_unsafe() throw (std::exception);
		void print_log(const Msg msg, std::ostream& strm);
		void send_log(const Msg msg);
		std::string format_str_msg(const Msg msg) const;
		static void init_default(struct sockaddr_storage& addr);
		static const char               default_fname_[];
		struct sockaddr_storage         addr_;
		std::vector<Msg>                ss_;

		SOCKET                          sock_;
		std::ofstream                   file_;
		std::ostream*                   stream_;

		std::mutex                      mtx_;
		std::mutex                      mtx_r_;
		char                            type_;

		bool                            truncmtu_;
		const size_t                    MTU_SAFE_PAYLOAD_SIZE_;
};

///////////////////////////////////////////////////////////////////////////
// inline

inline void
LogStream::init_default(struct sockaddr_storage& addr)
{
	struct sockaddr_in* addr_in = (struct sockaddr_in*)&addr;
	addr_in->sin_family = AF_INET;
	addr_in->sin_port = 0xcccc;
	addr_in->sin_addr.s_addr = inet_addr("127.0.0.1");

}

} // namespace

#endif // __LOGSTREAM_HPP__

