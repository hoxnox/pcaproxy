/* @author hoxnox <hoxnox@gmail.com>
 * @date 20130408 11:07:48
 *
 * Logger helpers definitions */

#ifndef __PCAPROXY_LOGGER_HPP__
#define __PCAPROXY_LOGGER_HPP__

#include <utils/NxSocket.h>
#include <utils/LogStream.hpp>

namespace pcaproxy {

/**@brief static storage for log routines*/
class Logger
{
	public:
		static LogStream elog;
		static LogStream ilog;
		static bool verbose;
};

class SilentNoop{
 public:
  SilentNoop() { }
  // This has to be an operator with a precedence lower than << but
  // higher than ?:
  void operator&(LogStream&) { }
};

#define ELOG Logger::elog < Logger::elog._stream()
#define ILOG Logger::ilog < Logger::ilog._stream()
#define VLOG !Logger::verbose ? (void) 0 : SilentNoop() & ILOG

#ifdef NDEBUG
#define ILOG_D \
	true ? (void) 0 : SilentNoop() & ILOG
#else // DEBUG
#define ILOG_D Logger::ilog < Logger::ilog._stream()
#endif // NDEBUG

} // namespace

#endif // __PCAPROXY_LOGGER_HPP__

