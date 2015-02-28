/* @author $username$ <$usermail$>
 * @date 20130408 11:07:48*/

#include <Logger.hpp>
#include <iostream>

namespace pcaproxy {

LogStream Logger::elog('E');
LogStream Logger::ilog('I');
bool Logger::verbose = false;

} // namespace

