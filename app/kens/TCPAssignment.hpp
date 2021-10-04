/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

typedef struct _Socket
{
  //process information
  int pid;
  int fd;

  //socket info
  int type;
  int protocol;
  uint32_t ip;
  int port;

  bool isBound;
  sockaddr addr;
  socklen_t addrlen;
} Socket;


class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  std::map<int, Socket *> sockets;
	std::map<std::pair<uint32_t, int>, int> sockfd_by_ip_port;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  // Our Implementation
  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int fd);
	void syscall_bind(UUID syscallUUID, int pid,
		int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	void syscall_getsockname(UUID syscallUUID, int pid,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  // void syscall_accept(UUID syscallUUID, int pid,
	// 	int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	// void syscall_connect(UUID syscallUUID, int pid,
	// 	int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	// void syscall_getpeername(UUID syscallUUID, int pid,
	// 	int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	// void syscall_listen(UUID syscallUUID, int pid,
	// 	int sockfd, int backlog);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
