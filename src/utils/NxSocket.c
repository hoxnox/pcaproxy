/**@author Kim Merder <hoxnox@gmail.com>
 * @date 20121015 11:39:14
 * @copyright Kim Merder */

#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <stdio.h>

#include "NxSocket.h"

/**@brief Set nonblocking mode
 * @return negative on error, 1 on success*/
int SetNonBlock(SOCKET sock)
{
#	ifdef WIN32
	u_long iMode = 1;
	ioctlsocket(sock, FIONBIO, &iMode);
#	else
	int flags;
	if( (flags = fcntl(sock, F_GETFL, 0)) < 0 )
		return -1;
	if( fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0 )
		return -2;
#	endif
	return 1;
}

/**@brief Enable broadcasting on socket
 * @return negative on error, 1 on success*/
int SetBroadcast(SOCKET sock)
{
	int on = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
		return -1;
	return 1;
}

/**@brief set reusable
 * @return negative on error, 1 on success*/
int SetReusable(SOCKET sock)
{
#ifdef WINSOCK
	char on = 1, off = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		return -1;
	// windows allow to bind the same port
	if(setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &off, sizeof(off)))
		return -1;
#else
	int on = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		return -1;
#endif
	/*
	if(setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, &off, sizeof(off)))
		return -1;
		*/
	return 1;
}

/**@brief get ipv4 type
 * @param ip - uint32_t ip representation in network byte order*/
IPv4Info GetIPv4Info(const uint32_t ip)
{
	IPv4Info result;
	uint32_t hostip = ntohl(ip);
	uint32_t netid = 0, hostid = 0;
	int private = 0;

	const uint32_t b1000 = (uint32_t)1  << 31; // 10000000 00000000 00000000 00000000
	const uint32_t b1100 = (uint32_t)3  << 30; // 11000000 00000000 00000000 00000000 
	const uint32_t b1110 = (uint32_t)7  << 29; // 11100000 00000000 00000000 00000000 
	const uint32_t b1111 = (uint32_t)15 << 28; // 11110000 00000000 00000000 00000000 

	const uint32_t anetmask  = (uint32_t)0x7f000000; // 01111111 00000000 00000000 00000000
	const uint32_t ahostmask = (uint32_t)0x00ffffff; // 00000000 11111111 11111111 11111111
	const uint32_t bnetmask  = (uint32_t)0x3fff0000; // 00111111 11111111 00000000 00000000
	const uint32_t bhostmask = (uint32_t)0x0000ffff; // 00000000 00000000 11111111 11111111
	const uint8_t  b1st_private = (uint8_t)0x3f & (uint8_t)172;  // 1-st byte of net id for private B networks
	const uint32_t cnetmask  = (uint32_t)0x1fffff00; // 00011111 11111111 11111111 00000000
	const uint32_t chostmask = (uint32_t)0x000000ff; // 00000000 00000000 00000000 11111111
	const uint8_t  c1st_private = (uint8_t)0x1f & (uint8_t)192; // 1-st byte of net id for private C networks

	result.net_type = IPv4_NETTYPE_UNKNOWN;
	result.addr_type = IPv4_ADDRTYPE_UNKNOWN; 
	
	if( (hostip & b1111) == b1110 )
	{
		result.addr_type = IPv4_ADDRTYPE_BROADCAST;
		return result;
	}
	if( (hostip & b1111) == b1111 )
	{
		result.addr_type = IPv4_ADDRTYPE_RESERVED;
		return result;
	}

	if((hostip & b1000) == 0)
	{
		netid  = (hostip & anetmask)/0x1000000;
		if(netid == 0)
			return result;
		hostid = (hostip & ahostmask);
		if( (hostip & anetmask) == anetmask )
			result.net_type = IPv4_NETTYPE_LOCAL;
		else
			result.net_type = IPv4_NETTYPE_A;
		if( hostid == ahostmask )
		{
			result.addr_type = IPv4_ADDRTYPE_BROADCAST;
			return result;
		}
		if(netid == 10)
			private = 1;
	}
	else if((hostip & b1100) == b1000)
	{
		result.net_type = IPv4_NETTYPE_B;
		netid  = (hostip & bnetmask)/0x10000;
		hostid = (hostip & bhostmask);
		if( hostid == bhostmask )
		{
			result.addr_type = IPv4_ADDRTYPE_BROADCAST;
			return result;
		}
		if(  netid/0x100 == b1st_private && 16 <= netid%0x100 && netid%0x100 <= 31)
			private = 1;
	}
	else if((hostip & b1110) == b1100)
	{
		result.net_type = IPv4_NETTYPE_C;
		netid  = (hostip & cnetmask);
		netid = netid/0x100;
		hostid = (hostip & chostmask);
		if( hostid == chostmask )
		{
			result.addr_type = IPv4_ADDRTYPE_BROADCAST;
			return result;
		}
		if(  netid/0x10000 == c1st_private && (netid%0x10000)/0x100 == 0xa8 )
			private = 1;
	}
	if(hostid == 0)
	{
		if(private)
			result.addr_type = IPv4_ADDRTYPE_NET_PRIVATE;
		else
			result.addr_type = IPv4_ADDRTYPE_NET;
	}
	else
	{
		if(private)
			result.addr_type = IPv4_ADDRTYPE_HOST_PRIVATE;
		else
			result.addr_type = IPv4_ADDRTYPE_HOST;
	}
	return result;
}

void* GetAddr(const struct sockaddr* addr)
{
	if(addr == NULL)
		return NULL;
	if(addr->sa_family == AF_INET)
		return &(((struct sockaddr_in *)addr)->sin_addr);
	if(addr->sa_family == AF_INET6)
		return &(((struct sockaddr_in6*)addr)->sin6_addr);
	return NULL;
}

void PrintSockInfo(SOCKET sock)
{
	struct sockaddr_storage addr;
	socklen_t addrln = sizeof(addr);
	char tmp[50];
	memset(&addr, 0, sizeof(addr));
	memset(tmp, 0, sizeof(tmp));

	printf("SOCKINFO:\n");
	if(!IS_VALID_SOCK(sock))
	{
		printf("Not valid socket\n");
		return;
	}
	printf("socket: %d\n", sock);
	if(getsockname(sock, (struct sockaddr*)&addr, &addrln) != 0)
	{
		printf("  bind: not binded\n");
		return;
	}
	if(!inet_ntop(addr.ss_family, GetAddr((struct sockaddr*)&addr), tmp, sizeof(tmp)))
	{
		printf("  bind: bind address corrupted\n");
		return;
	}
	printf("  bind: %s:%d", tmp, GetPort((struct sockaddr*)&addr));
}

unsigned short GetPort(const struct sockaddr* addr)
{
	if(addr->sa_family == AF_INET)
	{
		return ((struct sockaddr_in*)addr)->sin_port;
	}
	else if(addr->sa_family == AF_INET6)
	{
		return ((struct sockaddr_in6*)addr)->sin6_port;
	}
	else
		return 0;
}

void CopyStorageToSockaddr(const struct sockaddr_storage * st, struct sockaddr* sa)
{
	sa->sa_family = st->ss_family;
	if(st->ss_family == AF_INET)
	{
		((struct sockaddr_in*)sa)->sin_addr = ((const struct sockaddr_in*)st)->sin_addr;
		((struct sockaddr_in*)sa)->sin_port = ((const struct sockaddr_in*)st)->sin_port;
	}
	else if(sa->sa_family == AF_INET6)
	{
		((struct sockaddr_in6*)sa)->sin6_addr = ((const struct sockaddr_in6*)st)->sin6_addr;
		((struct sockaddr_in6*)sa)->sin6_port = ((const struct sockaddr_in6*)st)->sin6_port;
	}
}

void CopySockaddrToStorage(const struct sockaddr * sa, struct sockaddr_storage* st)
{
	st->ss_family = sa->sa_family;
	if(sa->sa_family == AF_INET)
	{
		((struct sockaddr_in*)st)->sin_addr = ((const struct sockaddr_in*)sa)->sin_addr;
		((struct sockaddr_in*)st)->sin_port = ((const struct sockaddr_in*)sa)->sin_port;
	}
	else if(sa->sa_family == AF_INET6)
	{
		((struct sockaddr_in6*)st)->sin6_addr = ((const struct sockaddr_in6*)sa)->sin6_addr;
		((struct sockaddr_in6*)st)->sin6_port = ((const struct sockaddr_in6*)sa)->sin6_port;
	}
}

/**@brief fill sockaddr_storage structure from parameters values
 * @param src - source, where to save data
 * @param addr - dotted notation of IP address
 * @param addrln - the addr length
 * @param port - port number (network byte order)
 * @return negative on error, 0 on success*/
int MakeSockaddr(struct sockaddr* src,
                 const char * addr,
                 const size_t addrln,
                 const unsigned short port)
{
	char * tmp = (char*)malloc((addrln + 1)*sizeof(char));
	memset(tmp, 0, addrln + 1);
	memcpy(tmp, addr, addrln);
	if(src == NULL || addr == NULL || addrln == 0)
		return -1;
	src->sa_family = GetFamily(addr, addrln);
	if( inet_pton(src->sa_family, tmp, GetAddr(src)) != 1 )
	{
		free(tmp);
		return -2;
	}
	free(tmp);
	((struct sockaddr_in6*)src)->sin6_port = port;
	return 0;
}

/**@brief fill sockaddr_storage structure from parameters values
 * @param src - source, where to save data
 * @param host - hostname (try to resolve host)
 * @param hostln - the hostname length
 * @param port - port number (network byte order)
 * @return negative on error, 0 on success*/
int ResolveSockaddr(struct sockaddr* src,
                    const char * host,
                    const size_t hostln,
                    const unsigned short port)
{
	// user getaddrinfo
	return 0;
}

/**@brief get address family by string representation
 * @param addr - address
 * @param addrln - the address length
 * @return AF_INET, if addr may be IPv4, AF_INET6 if IPv6 and -1 on error
 *
 * TODO: For now, this function just search for ':' sign, if it is here, we
 * expect IPv6 address, otherwise - IPv4.*/
int GetFamily(const char* addr, const size_t addrln)
{
	size_t i;
	if(addr == NULL || addrln == 0)
		return 0;
	for(i = 0; i < addrln; ++i)
		if(addr[i] == ':')
			return AF_INET6;
	return AF_INET;
}

