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

// #define SYN 2
// #define ACK 16
// #define FIN 1

namespace E {

  const int ACK = 1 << 4;
	const int RST = 1 << 2;
	const int SYN = 1 << 1;
	const int FIN = 1 << 0;

  enum TCP_STATE
  {
    INITIAL_STATE,
    CLOSED_STATE,
    LISTEN_STATE,
    SYN_RCVD_STATE,
    SYN_SENT_STATE,
    ESTABLISHED_STATE,
    CLOSE_WAIT_STATE,
    LAST_ACK_STATE,
    FIN_WAIT_1_STATE,
    FIN_WAIT_2_STATE,
    CLOSING_STATE,
    TIME_WAIT_STATE
  };

  typedef struct _DataInfo
	{
    sockaddr local_addr;
    sockaddr remote_addr;
		uint32_t seq_num;
		uint32_t ack_num;
    uint8_t data_ofs_ns;
    uint8_t flag;
	} DataInfo;

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
    enum TCP_STATE state;

    // For client
    DataInfo client_info;

    // Queue for listening socket
    std::queue<Packet> *listen_queue;
		std::queue<DataInfo> *accept_queue;
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
    ConnectParam connect_param;
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
  // (pid, sockfd) -> DataInfo
  std::map<std::pair<int, int>, DataInfo> data_info_by_pid_sockfd;
  // (pid) -> (Process) (Note: ONLY BLOCKED PROCESS IS HERE)
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

    void read_packet_header(Packet *packet, DataInfo *c);

    void write_packet_header(Packet *new_packet, DataInfo *c);

    void write_packet_response(Packet *new_packet, DataInfo *sc, DataInfo *rc);

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
