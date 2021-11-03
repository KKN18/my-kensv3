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


  enum TCP_STATE
  {
    INIT_STATE,
    CLOSED_STATE,
    LISTEN_STATE,
    SYN_RCVD_STATE,
    SYN_SENT_STATE,
    ESTAB_STATE
  };

  typedef struct _DataInfo
	{
    in_addr_t local_ip;
    in_port_t local_port;
    sockaddr local_addr;
    in_addr_t remote_ip;
    in_port_t remote_port;
    sockaddr remote_addr;
		uint32_t seq_num;
		uint32_t ack_num;
    uint8_t header_length;
    uint8_t flag;
	} DataInfo;

  typedef struct _Socket
  {
    int pid;
    int fd;

    int type;
    int protocol;
    // uint32_t ip;
    // int port;
    in_addr_t ip;
    in_port_t port;

    bool isBound;
    sockaddr addr;
    socklen_t addrlen;

    // State
    enum TCP_STATE state;

    // For client
    sockaddr connect_addr;

    std::queue<Packet> *listenQueue;
		std::queue<DataInfo> *acceptQueue;
    unsigned int backlog;

    // For read, write
    char *receive_buffer;
    char *receive_ptr;
    bool is_rcvd_data;
    char *send_buffer;
    bool enough_send_space;
  } Socket;

  typedef struct _Process
  {
    sockaddr *addr;
    socklen_t *addrlen;
		UUID syscallUUID;
  } Process;

  typedef struct _IOProcess
  {
    int fd;
    void *buf;
    size_t count;
    UUID syscallUUID;
  } IOProcess;

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
  // (ip, port) -> (pid, sockfd)
  std::map<std::pair<in_addr_t, in_port_t>, std::pair<int, int>> estab_pid_sockfd_by_ip_port;
  // (pid, sockfd) -> DataInfo
  std::map<std::pair<int, int>, DataInfo> data_infos;
  // (pid) -> (Process) (Note: ONLY BLOCKED PROCESS IS HERE)
  std::map<int, Process> blocked_process_table;
  // (pid, fd) -> (IOProcess) (Note: ONLY BLOCKED PROCESS IS HERE)
  std::map<std::pair<int, int>, IOProcess> blocked_io_table;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  // Our Implementation
  ssize_t syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);
  ssize_t syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);
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
  std::pair<in_addr_t, in_port_t> divide_addr(sockaddr addr);

  sockaddr unit_addr(in_addr_t ip, in_port_t port);

  void read_packet_header(Packet *packet, DataInfo *c);

  void write_packet_header(Packet *new_packet,
    size_t ip_start, size_t tcp_start,
    in_addr_t local_ip, in_addr_t remote_ip,
    in_port_t local_port, in_port_t remote_port);

  void write_packet_response(Packet *new_packet,
    size_t ip_start, size_t tcp_start,
    uint8_t new_flag, uint32_t new_seq_num, uint32_t new_ack_num,
    in_addr_t local_ip, in_addr_t remote_ip);

  void write_packet_header_mod(Packet *new_packet, DataInfo *c);

  void write_packet_response_mod(Packet *new_packet, DataInfo *sc, DataInfo *rc);

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
