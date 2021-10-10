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
// Can I use stdlib.h?
#include <stdlib.h>

namespace E {

  const static int MAX_PORT_NUM = 65536;

  const int ACK = 1 << 4;
  const int RST = 1 << 2;
  const int SYN = 1 << 1;
  const int FIN = 1 << 0;



  enum TCPState
  {
    ST_READY, 		/* Socket is ready. */
    ST_LISTEN,		/* Connect ready. Only for server. */
    ST_SYN_SENT,	/* 3-way handshake, client. */
    ST_SYN_RCVD,	/* 3-way handshake, server. */
    ST_ESTAB,		/* Connection established. */

    ST_FIN_WAIT_1,	/* 4-way handshake, active close. */
    ST_FIN_WAIT_2,
    ST_TIME_WAIT,
    ST_CLOSE_WAIT,	/* 4-way handshake, passive close. */
    ST_LAST_ACK,

    ST_CLOSING		/* Recieved FIN after sending FIN. */
  };

  typedef struct _Context
	{
		// sockaddr local_addr;
    in_addr_t local_ip;
    in_port_t local_port;
    sockaddr local_addr;
    in_addr_t remote_ip;
    in_port_t remote_port;
    sockaddr remote_addr;
		uint32_t seq_num;
		uint32_t ack_num;
	} Context;

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

    // State
    enum TCPState state;

    // For client
    Context client_context;

    // Queue for listening socket
    std::queue<Packet> *listen_queue;
		std::queue<Context> *accept_queue;
    unsigned int backlog;
  } Socket;

  typedef struct _CloseParam
  {
    int fd;
    sockaddr *addr;
    socklen_t *addrlen;
  } CloseParam;

  typedef struct _AcceptParam
  {
    int fd;
    sockaddr *addr;
    socklen_t *addrlen;
  } AcceptParam;

  typedef struct _ConnectParam
  {
    int fd;
    sockaddr *addr;
    socklen_t *addrlen;
  } ConnectParam;

  typedef struct _Process
  {
    bool isBlocked;
    int syscall;
		UUID syscallUUID;
    AcceptParam accept_param;
  } Process;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  // (pid, sockfd) -> Socket
  std::map<std::pair<int, int>, Socket> sockets;
  // (ip, port) -> (pid, sockfd)
	std::map<std::pair<in_addr_t, in_port_t>, std::pair<int, int>> pid_sockfd_by_ip_port;
  // (pid, sockfd) -> Context
  std::map<std::pair<int, int>, Context> contexts;
  // (pid) -> (Process)
  std::map<int, Process> process_table;

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
  void syscall_accept(UUID syscallUUID, int pid,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_connect(UUID syscallUUID, int pid,
		int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_listen(UUID syscallUUID, int pid,
		int sockfd, int backlog);

    // Utility Functions
    std::pair<in_addr_t, in_port_t> untie_addr(sockaddr addr);

    sockaddr tie_addr(in_addr_t ip, in_port_t port);

    void read_packet_header(Packet *packet,
      size_t ip_start, size_t tcp_start,
      in_addr_t *local_ip, in_addr_t *remote_ip,
      in_port_t *local_port, in_port_t *remote_port,
      uint32_t *seq_num, uint32_t *ack_num,
      uint8_t *data_ofs_ns, uint8_t *flag);

    void write_packet_header(Packet *new_packet,
      size_t ip_start, size_t tcp_start,
      in_addr_t local_ip, in_addr_t remote_ip,
      in_port_t local_port, in_port_t remote_port);

    void write_packet_response(Packet *new_packet,
      size_t ip_start, size_t tcp_start,
      uint8_t new_flag, uint32_t new_seq_num, uint32_t new_ack_num,
      in_addr_t local_ip, in_addr_t remote_ip);

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
