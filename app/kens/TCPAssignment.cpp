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
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    break;
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
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
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
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

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol, int trash)
{
	//assert(domain == AF_INET && protocol == IPPROTO_TCP);
	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
		fd_set.insert(fd);

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	auto it1 = fd_set.find(fd);
	if(it1 == fd_set.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	fd_set.erase(it1);

	auto it2 = fd_info.find(fd);
	if(it2 != fd_info.end())
	{
		uint32_t ip;
		unsigned short int port;

		std::tie(ip, port) = it2->second;
		fd_info.erase(it2);
		fd_info_raw.erase(fd);

		if(ip == INADDR_ANY)
			is_addr_any[port] = false;
		else
			ip_set[port].erase(ip);
	}

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if(fd_set.find(sockfd) == fd_set.end() || fd_info_raw.find(sockfd) != fd_info_raw.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	uint32_t ip;
	unsigned short int port;

	ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	port = ((struct sockaddr_in *)addr)->sin_port;

	if(ip == INADDR_ANY)
	{
		if(is_addr_any[port] || !ip_set[port].empty())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		is_addr_any[port] = true;
	}
	else if(is_addr_any[port] || !ip_set[port].insert(ip).second)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	fd_info[sockfd] = { ip, port };
	fd_info_raw[sockfd] = { *addr, addrlen };
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto it = fd_info_raw.find(sockfd);
	if(it == fd_info_raw.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	*addr = it->second.first;
	*addrlen = it->second.second;

	this->returnSystemCall(syscallUUID, 0);
}
} // namespace E
