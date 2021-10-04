/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case CONNECT:
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    // 		static_cast<struct sockaddr*>(param.param2_ptr),
    // (socklen_t)param.param3_int);
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    break;
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    // 		static_cast<struct sockaddr*>(param.param2_ptr),
    // 		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		(socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    // 		static_cast<struct sockaddr *>(param.param2_ptr),
    // 		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

/*
The socket() call receives 3 parameters from the application layer. Now it should create a file
descriptor and store the domain and the protocol in the data structure indexed by the file
descriptor. It returns the file descriptor. More details about the socket call are described at:
https://linux.die.net/man/2/socket and https://linux.die.net/man/3/socket. In KENS, you need
to implement only domain AF_INET, type SOCK_STREAM, and protocol IPPROTO_TCP.
*/
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	// assert(domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP);
  if(domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
    errno = EACCES;
    this->returnSystemCall(syscallUUID, -1);
  }

  Socket *t = (Socket *)malloc(sizeof(Socket));

	int fd = this->createFileDescriptor(pid);

  if (fd < 0)
    return;

  t->pid = pid;
  t->fd = fd;
  t->type = type;
  t->protocol = protocol;
  t->isBound = false;

  sockets[fd] = t;

	this->returnSystemCall(syscallUUID, fd);
}

/*
The close() call receives a parameter from the application layer. It closes the file descriptor’s
connection and deallocates the file descriptor. More details about the socket call are
described https://linux.die.net/man/2/close and https://linux.die.net/man/3/close.
*/
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	// auto it1 = fd_list.find(fd);
	// if(it1 == fd_list.end())
	// {
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }
	// fd_list.erase(fd);
  // fd_list.erase(it1);

  auto iter = sockets.find(fd);
  if(iter != sockets.end())
  {
    Socket *s = iter->second;

    uint32_t ip;
    int port;

    // std::tie(ip, port) = it2->first;
    ip = s->ip;
    port = s->port;
    sockets.erase(iter);
    sockfd_by_ip_port.erase(std::pair<uint32_t, int>(ip, port));
    free(s);
  }

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

/*
The connect() call receives 3 parameters from the application layer. It connects the file
descriptor to the address specified by addr. More details about the socket call are described
https://linux.die.net/man/2/connect and https://linux.die.net/man/3/connect.

// */
// void syscall_connect(UUID syscallUUID, int pid,
// 	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
// {
//   return;
// }
//
// /*
// The listen() call receives 2 parameters from the application layer. It marks the socket as a
// passive socket, that is, as a socket that will be used to accept incoming connection requests
// using accept. KENS requires you to implement the backlog parameter. It defines the
// maximum length to which the queue of pending connections for sockfd may grow. More
// details about the socket call are described https://linux.die.net/man/2/listen and
// https://linux.die.net/man/3/listen.
//
// */
// void syscall_listen(UUID syscallUUID, int pid,
// 	int sockfd, int backlog)
// {
//   return;
// }
//
// /*
// The accept() call receives 3 parameters from the application layer. It extracts the first
// connection on the queue of pending connections. It creates and returns a new file descriptor
// for the connection. It also fills the address parameter with connecting client’s information.
// More details about the socket call are described https://linux.die.net/man/2/accept and
// https://linux.die.net/man/3/accept .
// */
// void syscall_accept(UUID syscallUUID, int pid,
// 	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
// {
//   return;
// }

/*
The bind() call receives 3 parameters from the application layer. Now it should assign an
address to the socket. More details about the socket call are described
https://linux.die.net/man/2/bind and https://linux.die.net/man/3/bind .
In KENS, you need to implement only sockaddr_in type for sockaddr.

// struct sockaddr_in {
// sa_family_t sin_family;  // address family: AF_INET
// in_port_t sin_port;  // port in network byte order
// struct in_addr sin_addr;  // internet address
// };
// // Internet address.
// struct in_addr {
// uint32_t s_addr; // address in network byte order
// };

The only value you should assign to sin_family is AF_INET. The two fields, sin_port and
sin_addr, must follow the network byte order. The sin_addr field must be either an IP
address or INADDR_ANY. You should implement both cases.
*/
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  // Error: No sockets found
  auto iter = sockets.find(sockfd);
  if(iter == sockets.end()) {
    this->returnSystemCall(syscallUUID, -1);
  }

  // Error: socket is already bound to an address
  if (iter->second->isBound){
    this->returnSystemCall(syscallUUID, -1);
  }

	uint32_t ip;
	int port;

	ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	port = ((struct sockaddr_in *)addr)->sin_port;

  // If it's not INADDR_ANY
  // if ip == INADDR_ANY (ip = 0)
  auto iter2 = sockfd_by_ip_port.find(std::pair<uint32_t, int>(ip, port));
	if(iter2 != sockfd_by_ip_port.end())
		this->returnSystemCall(syscallUUID, -1);

	//Check if INADDR_ANY is already using the port
  iter2 = sockfd_by_ip_port.find(std::pair<uint32_t, int>(0, port));
	if (iter2 != sockfd_by_ip_port.end())
    this->returnSystemCall(syscallUUID, -1);

	// if(ip == INADDR_ANY)
	// {
	// 	if(is_addr_any[port] || !ip_list[port].empty())
	// 	{
	// 		this->returnSystemCall(syscallUUID, -1);
	// 		return;
	// 	}
  //
	// 	is_addr_any[port] = true;
	// }
	// else if(is_addr_any[port] || !ip_list[port].insert(ip).second)
	// {
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }

	// fd_info[sockfd] = { ip, port };
	// fd_info_raw[sockfd] = { *addr, addrlen };

  Socket *s = iter->second;

  s->isBound = true;
  s->ip = ip;
  s->port = port;
  s->addr = *addr;
  s->addrlen = addrlen;

  sockfd_by_ip_port[std::pair<uint32_t, int>(ip, port)] = sockfd;

  // sockfd_info[sockfd] = {{ip, port}, {*addr, addrlen}};

	this->returnSystemCall(syscallUUID, 0);
}

/*
The getsockname() call receives 3 parameters from the application layer. It should return the
current address to which the socket is bound. More details about the socket call are
described https://linux.die.net/man/2/getsockname and
https://linux.die.net/man/3/getsockname. As in the case of bind(), you need to implement
only the sockaddr_in type for sockaddr.
*/
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	// auto it = fd_info_raw.find(sockfd);
	// if(it == fd_info_raw.end())
	// {
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }
  //
	// *addr = it->second.first;
	// *addrlen = it->second.second;
  //
	// this->returnSystemCall(syscallUUID, 0);

  auto iter = sockets.find(sockfd);
  // Error: No sockets found
	if(iter == sockets.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
  // Error: Socket is not bound
	if(!(iter->second->isBound))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

  Socket *s = iter->second;

  *addr = s->addr;
  *addrlen = s->addrlen;

	this->returnSystemCall(syscallUUID, 0);
}

} // namespace E
