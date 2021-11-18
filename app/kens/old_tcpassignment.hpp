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
    ESTAB_STATE,
    FIN_STATE
  };

  typedef struct _DataInfo
	{
    sockaddr local_addr;
    sockaddr remote_addr;
		uint32_t seq_num;
		uint32_t ack_num;
    uint16_t total_length;
    uint16_t checksum;
    uint8_t ihl;
    uint8_t data_ofs;
    uint8_t flag;
	} DataInfo;

  typedef struct _Socket
  {
    int pid;
    int fd;
    int type;
    int protocol;

    bool isBound;
    uint16_t window;

    // State
    enum TCP_STATE state;

    sockaddr local_addr;
    // Remote addr Info after 3-way handshake
    sockaddr remote_addr;
    bool is_connected;

    std::queue<Packet> *listenQueue;
		std::queue<DataInfo> *acceptQueue;
    unsigned int backlog;

    /* For Receiver */
    char *receive_buffer;
    // pakcets
    char *packet_ptr;
    // within one packet
    char *data_ptr;
    size_t remaining;
    bool is_rcvd_data;
    uint32_t expect_seq_num;
    uint32_t expect_ack_num;

    /* For Sender */
    char *send_buffer;
    // packets ptr
    char *send_ptr;
    // recently acked packet ptr
    char *acked_ptr;

    size_t send_remaining;
    bool enough_send_space;
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t retransmit_ack;

    /* For Timer Implementation */
    UUID timerUUID;
    Time sent_time;
    Time estimated_rtt;
    Time dev_rtt;
    Time timeout_interval;

    uint32_t timer_seq_num;

    bool timer_alive;

    std::queue<std::pair<uint32_t, uint32_t>> *seqnumQueue;

    // queue of inflight packets, aka pakcets that are sent but not acked.
    std::list<std::pair<uint32_t, uint32_t>> *inflight_packets_info;

  } Socket;

  typedef struct _Process
  {
    sockaddr *addr;
    socklen_t *addrlen;
		UUID syscallUUID;
  } Process;

  typedef struct _ReadProcess
  {
    int fd;
    void *buf;
    size_t count;
    UUID syscallUUID;
  } ReadProcess;

  typedef struct _WriteProcess
  {
    int fd;
    const void *buf;
    size_t count;
    UUID syscallUUID;
  } WriteProcess;

  typedef struct _CloseProcess
  {
    int fd;
    UUID syscallUUID;
  } CloseProcess;

  typedef struct _Timer_Payload_Info
  {
    uint32_t seq_num;
    uint32_t ack_num;
    int pid;
    int fd;
    Time timeout_interval;
  } Timer_PayLoad_Info;

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
  // (pid, fd) -> (IOProcess) (Note: ONLY READ BLOCKED PROCESS IS HERE)
  std::map<std::pair<int, int>, ReadProcess> blocked_read_table;
  // (pid, fd) -> (IOProcess) (Note: ONLY WRITE BLOCKED PROCESS IS HERE)
  std::map<std::pair<int, int>, WriteProcess> blocked_write_table;
  // (pid, fd) -> (IOProcess) (Note: ONLY CLOSE BLOCKED PROCESS IS HERE)
  std::map<std::pair<int, int>, CloseProcess> blocked_close_table;
  // set of (seq_num, ack_num) (Note: RECEIVED PACKETS)
  std::set<std::pair<uint32_t, uint32_t>> unique_packets;
  // (seq_num, ack_num) -> (Packet) (Note: SENT PACKETS THAT ARE ACKED)
  std::map<std::pair<uint32_t, uint32_t>, Packet> sent_packets;


public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  /* System Calls */
  void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);
  void syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);
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

  /* Packet Managing Functions */
  void manage_init(Packet *packet, Socket *socket);
  void manage_listen(Packet *packet, Socket *socket);
  void manage_synsent(Packet *packet, Socket *socket);
  void manage_synrcvd(Packet *packet, Socket *socket);
  void manage_estab(Packet *packet, Socket *socket);
  void manage_fin(Packet *packet, Socket *socket);

  /* Timer Calculation */
  void calculate_timeout_interval(Socket *socket, Time sample_rtt);

  /* Utility Functions For Packet Manipulation */
  // Generate or Read SockAddr
  std::pair<in_addr_t, in_port_t> divide_addr(sockaddr addr);
  sockaddr unit_addr(in_addr_t ip, in_port_t port);

  // Read and Write Packet Header
  void read_packet_header(Packet *packet, DataInfo *c);
  void write_packet_header(Packet *new_packet, DataInfo *c);
  void write_packet_header_without_checksum(Packet *new_packet, DataInfo *info);
  void write_packet_header_mod(Packet *new_packet,
    size_t ip_start, size_t tcp_start,
    in_addr_t local_ip, in_addr_t remote_ip,
    in_port_t local_port, in_port_t remote_port);

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
