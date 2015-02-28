/**@author Nosov Yuri <hoxnox@gmail.com>
 * @date 20120412
 *
 * This header is used to minimize interface differences between BSD sockets and windows sockets.*/

/**@define WINSOCK
 * @brief Defined, if Windows sockets is used.*/

/**@define BSDSOCK
 * @brief Defined, if BSD sockets is used*/

/**@define IS_VALID_SOCK()
 * @brief Check socket state.*/

/**@define GET_LAST_SOCK_ERROR()
 * @brief Get last error code.*/

/**@define SOCK_INIT()
 * @brief Make initialization*/

#include <stdint.h>

#ifdef WIN32 
#	ifndef WINSOCK
#		define WINSOCK
#	endif
#else
#	ifndef BSDSOCK
#		define BSDSOCK
#	endif
#endif

#ifdef WINSOCK
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef BSDSOCK
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#endif

#ifndef __NX_SOCKET_H__
#define __NX_SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BSDSOCK
typedef int SOCKET;
#define INVALID_SOCKET -1
#	define IS_VALID_SOCK(s) (s >= 0)
#	define GET_LAST_SOCK_ERROR() (errno)
#	define SOCK_INIT()
#endif

#ifdef WINSOCK
#	define IS_VALID_SOCK(s) (s != INVALID_SOCKET)
#	define GET_LAST_SOCK_ERROR() (WSAGetLastError())
#	define SOCK_INIT() \
{ \
	WSADATA wsaData; \
	WSAStartup(MAKEWORD(1, 1), &wsaData); \
}

/*
#	define EINTR         WSAEINTR
#	define EBADF         WSAEBADF
#	define EINVAL        WSAEINVAL
#	define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#	define EADDRINUSE    WSAEADDRINUSE
#	define EHOSTUNREACH  WSAEHOSTUNREACH
#	define ENETUNREACH   WSAENETUNREACH
#	define ECONNREFUSED  WSAECONNREFUSED
#	define ECONNRESET    WSAECONNRESET
*/

#endif

typedef enum {
	IPv4_NETTYPE_A         = 1,
	IPv4_NETTYPE_B         = 2,
	IPv4_NETTYPE_C         = 3,
	IPv4_NETTYPE_LOCAL     = 4,
	IPv4_NETTYPE_UNKNOWN   = 0
} IPv4NetType;

typedef enum {
	IPv4_ADDRTYPE_RESERVED       = 1,
	IPv4_ADDRTYPE_BROADCAST      = 2,
	IPv4_ADDRTYPE_HOST           = 3,
	IPv4_ADDRTYPE_HOST_PRIVATE   = 4,
	IPv4_ADDRTYPE_NET            = 5,
	IPv4_ADDRTYPE_NET_PRIVATE    = 6,
	IPv4_ADDRTYPE_UNKNOWN        = 0
} IPv4AddrType;

typedef struct
{
	IPv4NetType  net_type;
	IPv4AddrType addr_type;
} IPv4Info;


int            SetNonBlock(SOCKET sock);
int            SetReusable(SOCKET sock);
int            SetBroadcast(SOCKET sock);
IPv4Info       GetIPv4Info(const uint32_t ip);
unsigned short GetPort(const struct sockaddr* addr);
void*          GetAddr(const struct sockaddr* addr);
void           PrintSockInfo(SOCKET sock);
void           CopyStorageToSockaddr(const struct sockaddr_storage * st, struct sockaddr* sa);
void           CopySockaddrToStorage(const struct sockaddr * sa, struct sockaddr_storage* st);
int            MakeSockaddr(struct sockaddr* src,
                            const char * addr,
                            const size_t addrln,
                            const unsigned short port);
int            ResolveSockaddr(struct sockaddr* src,
                               const char * host,
                               const size_t hostln,
                               const unsigned short port);
int            GetFamily(const char* addr, const size_t addrln);

#ifdef __cplusplus
}
#endif

#endif // __NX_SOCKET_H__

