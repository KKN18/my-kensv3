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

#define FUNCTION_LOG 1
#define STATE_LOG 1
#define LOG 1
#define IP_START 14
#define TCP_START 34
#define HEADER_SIZE 54
#define WINDOW_SIZE 51200
#define DATA_OFS 20
#define RECEIVE_BUFFER_SIZE 2097152 // 2*1024*1024
#define SEND_BUFFER_SIZE 2097152 // 2*1024*1024
#define MSS 1460

#define ACK 16
#define SYN 2
#define FIN 1

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
  // if(FUNCTION_LOG) {
  //   printf("(pid: %d) systemCallback\n", pid);
  // }

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int,
    param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
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
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  if(LOG) {
    printf("\npacketArrived=========================\n");
  }
  /* Read Packet START */
  assert(fromModule == "IPv4");

  DataInfo received_info;
  read_packet_header(&packet, &received_info);

  in_addr_t local_ip;
  in_port_t local_port;
  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);

  auto iter = estab_pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(local_ip, local_port));
  if(iter == estab_pid_sockfd_by_ip_port.end())
  {
    iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(0, local_port));
    if(iter == pid_sockfd_by_ip_port.end())
    {
        iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(local_ip, local_port));
        if (iter == pid_sockfd_by_ip_port.end())
        {
          return;
          // assert(0);
        }
    }
  }
  auto iter2 = sockets.find({iter->second.first, iter->second.second});
  assert(iter2 != sockets.end());

  auto &s = iter2->second;
  s.pid = iter->second.first;
  s.fd = iter->second.second;
	switch(s.state)
	{
		case INIT_STATE:
      manage_init(&packet, &s);
			break;
		case LISTEN_STATE:
      manage_listen(&packet, &s);
      break;
		case SYN_SENT_STATE:
      manage_synsent(&packet, &s);
      break;
		case SYN_RCVD_STATE:
      manage_synrcvd(&packet, &s);
      break;
    case ESTAB_STATE:
      manage_estab(&packet, &s);
      break;
		default:
			assert(0);
	}
  return;
}

void TCPAssignment::timerCallback(std::any payload) {
  if(FUNCTION_LOG) {
    printf("timerCallback\n");
  }
  // Remove below
  (void)payload;
}

ssize_t TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_read\n", pid);
  }

  Socket &s = sockets[{pid, fd}];

  if (s.is_rcvd_data){
      IOProcess &p = blocked_io_table[{pid, fd}];

      if(s.remaining == 0) {
          s.is_rcvd_data = false;
          this->returnSystemCall(syscallUUID, 0);
          return 0;
      }

      size_t read_byte = count > s.remaining ? s.remaining : count;
      memcpy(buf, s.data_ptr, read_byte);
      s.data_ptr += read_byte;
      s.remaining -= read_byte;
      this->returnSystemCall(syscallUUID, read_byte);
      return read_byte;
  }
  else {
      IOProcess read_p;
      read_p.fd = fd;
      read_p.buf = buf;
      read_p.count = count;
      read_p.syscallUUID = syscallUUID;
      blocked_io_table[{pid, fd}] = read_p;
      return count;
  }
}

ssize_t TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count)
{
  this->returnSystemCall(syscallUUID, fd);
  return count;

  Socket &s = sockets[{pid, fd}];

  // (1) If there is enough space in the corresponding TCP socket’s send buffer for the data, the data is copied to the send buffer.
  if(s.send_remaining >= count)
  {
    // (a) if the data is sendable (i.e., the data lies in the sender’s window, send the data and the call returns.
    if(s.send_ptr - s.acked_ptr < s.window){
      memcpy(s.send_ptr, buf, count);
      s.send_ptr += count;
      DataInfo info;
      info.local_addr = s.local_addr;
      info.remote_addr = s.remote_addr;
      info.seq_num = s.seq_num; info.ack_num = 1;

      Packet packet(HEADER_SIZE + count);
      write_packet_header(&packet, &info);

      uint16_t size = count;
      uint8_t buf = size >> 8;
      packet.writeData(IP_START + 2, &buf, 1);
      buf = (uint8_t)(size & 0xFF);
      packet.writeData(IP_START + 3, &buf, 1);

    }

    // (b) if the data is not sendable (i.e., the data lies outside the sender’s window), the call just returns.


  }
  // (2) If there is not enough space, the call blocks until the TCP layer receives ACK(s) and  releases sufficient space for the data.
  // When sufficient space for the given (from application) data becomes available, the data is copied to the send buffer
  else
  {

  }
  return;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_socket\n", pid);
  }

	assert(domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP);

	int fd = this->createFileDescriptor(pid);
  assert(fd >= 0);

  Socket s;
  s.pid = pid;
  s.fd = fd;
  s.type = type;
  s.protocol = protocol;
  s.isBound = false;
  s.state = INIT_STATE;
  s.receive_buffer = (char *) malloc(RECEIVE_BUFFER_SIZE * sizeof(char));
  s.send_buffer = (char *) malloc(SEND_BUFFER_SIZE * sizeof(char));
  s.is_rcvd_data = false;
  s.enough_send_space = true;
  s.packet_ptr = s.receive_buffer;
  s.data_ptr = s.receive_buffer;
  s.remaining = 0;
  // Fixed window size
  s.window = 51200;
  s.seq_num = 1;
  s.send_ptr = s.send_buffer;
  s.ack_ptr = s.send_buffer;

  sockets[{pid, fd}] = s;

	this->returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_close\n", pid);
  }

  auto iter = sockets.find({pid, fd});
  assert(iter != sockets.end());

  auto &s = iter->second;

  in_addr_t ip;
  in_port_t port;

  ip = s.ip;
  port = s.port;

  // Free malloced memory in syscall_socket
  free(s.receive_buffer);
  free(s.send_buffer);

  sockets.erase(iter);
  pid_sockfd_by_ip_port.erase(std::pair<in_addr_t, in_port_t>(ip, port));

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_connect\n", pid);
  }

  auto iter = sockets.find({pid, sockfd});
  if(iter == sockets.end()) {
    this->returnSystemCall(syscallUUID, -1);
  }

  Process p;
  p.syscallUUID = syscallUUID;
  blocked_process_table[pid] = p;

  auto &s = iter->second;
  s.remote_addr = *addr;

  in_addr_t remote_ip, local_ip;
  in_port_t remote_port, local_port;

  std::tie(remote_ip, remote_port) = divide_addr(*addr);

  in_addr_t network_remote_ip = htonl(remote_ip);

  char remote_ip_buffer[20];
  inet_ntop(AF_INET, &network_remote_ip, remote_ip_buffer, sizeof(remote_ip_buffer));

  ipv4_t converted_remote_ip;

  sscanf(remote_ip_buffer, "%c.%c.%c.%c", &converted_remote_ip[0],
    &converted_remote_ip[1], &converted_remote_ip[2], &converted_remote_ip[3]);

  if (!s.isBound){
  	int table_port = getRoutingTable(converted_remote_ip);
    std::optional<ipv4_t> local_ip_array = getIPAddr(table_port);
    assert(local_ip_array.has_value() == true);

    char local_ip_buffer[20];
    memset(local_ip_buffer, 0, sizeof(local_ip_buffer));

    for (int i=3; i>=0; i--) {
      std::string buf = std::to_string((*local_ip_array)[i]);
      strcat(local_ip_buffer, buf.c_str());
      if(i != 0)
        strcat(local_ip_buffer, ".");
    }

    inet_pton(AF_INET, local_ip_buffer, &local_ip);

    /* Find port that is not taken yet */
    for(int i=65535; i>0; i--) {
      local_port = i;
      if (pid_sockfd_by_ip_port.find({local_ip, local_port}) == pid_sockfd_by_ip_port.end()
            && pid_sockfd_by_ip_port.find({0, local_port}) == pid_sockfd_by_ip_port.end())
  			break;
    }

    pid_sockfd_by_ip_port[{local_ip, local_port}] = {pid, sockfd};
    s.ip = local_ip;
    s.port = local_port;
    s.isBound = true;
    s.addr = unit_addr(local_ip, local_port);
    s.addrlen = sizeof(s.addr);
  }
  else {
    local_ip = s.ip;
    local_port = s.port;
  }

  in_addr_t local_ip_converted = htonl(local_ip);
  in_addr_t remote_ip_converted = htonl(remote_ip);

  Packet packet(HEADER_SIZE);

  // TODO: Simplify here
  /* Writing Packet */
  uint32_t rand_num = rand();
  uint32_t seq_num = htonl(rand_num);
  uint8_t flag = SYN;

  packet.writeData(TCP_START + 4, &seq_num, 4);
  packet.writeData(TCP_START + 13, &flag, 1);
  write_packet_header_mod(&packet, IP_START, TCP_START, local_ip,
    remote_ip, local_port, remote_port);

  uint8_t tcp_data[DATA_OFS];
  packet.readData(TCP_START, tcp_data, DATA_OFS);

  uint16_t checksum = ~NetworkUtil::tcp_sum(local_ip_converted, remote_ip_converted, tcp_data, DATA_OFS);
  uint16_t checksum_converted = htons(checksum);
  packet.writeData(TCP_START + 16, &checksum_converted, 2);
  /* Writing packet finished */
  sendPacket("IPv4", std::move(packet));
  s.state = SYN_SENT_STATE;
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_listen\n", pid);
  }

	auto sock_it = sockets.find({pid, sockfd});
  assert(sock_it != sockets.end());
  assert(sock_it->second.isBound == true);
  assert(backlog > 0 && backlog < 127);

  auto &s = sock_it->second;

	s.state = LISTEN_STATE;
  s.listenQueue = new std::queue<Packet>;
  s.acceptQueue = new std::queue<DataInfo>;
  s.backlog = (unsigned int) backlog;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_accept\n", pid);
  }

  auto sock_it = sockets.find({pid, sockfd});
  assert(sock_it != sockets.end());

  auto &s = sock_it->second;

  int fd = this->createFileDescriptor(pid);
  assert(fd >= 0);

  if(s.acceptQueue->empty())
  {
    Process p;

    p.syscallUUID = syscallUUID;
    p.addr = addr;
    p.addrlen = addrlen;

    blocked_process_table[pid] = p;

    return;
  }

  DataInfo info = s.acceptQueue->front();
  s.acceptQueue->pop();

  Socket new_socket;
  std::tie(new_socket.ip, new_socket.port) = divide_addr(info.local_addr);
  new_socket.addr = info.local_addr;
  new_socket.addrlen = sizeof(info.local_addr);
  new_socket.isBound = true;
  new_socket.receive_buffer = (char *) malloc(RECEIVE_BUFFER_SIZE * sizeof(char));
  new_socket.send_buffer = (char *) malloc(SEND_BUFFER_SIZE * sizeof(char));
  new_socket.is_rcvd_data = false;
  new_socket.packet_ptr = new_socket.receive_buffer;
  new_socket.data_ptr = new_socket.receive_buffer;
  new_socket.remaining = 0;
  new_socket.window = 51200;
  new_socekt.seq_num = 1;
  new_socket.send_ptr = new_socket.send_buffer;
  new_socket.ack_ptr = new_socket.send_buffer;

  *addr = info.local_addr;
  *addrlen = sizeof(*addr);

  new_socket.local_addr = info.local_addr;
  new_socket.remote_addr = info.remote_addr;
  sockets[{pid, fd}] = new_socket;
  estab_pid_sockfd_by_ip_port[{new_socket.ip, new_socket.port}] = {pid, fd};

  this->returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_bind\n", pid);
  }
  // Error: No sockets found
  auto iter = sockets.find({pid, sockfd});
  if(iter == sockets.end()) {
    this->returnSystemCall(syscallUUID, -1);
  }

  // Error: socket is already bound to an address
  if (iter->second.isBound){
    this->returnSystemCall(syscallUUID, -1);
  }

	in_addr_t ip;
	in_port_t port;

  std::tie(ip, port) = divide_addr(*addr);

  // If it's not INADDR_ANY
  // if ip == INADDR_ANY (ip = 0)
  auto iter2 = pid_sockfd_by_ip_port.find(std::pair<in_addr_t, in_port_t>(ip, port));
	if(iter2 != pid_sockfd_by_ip_port.end())
		this->returnSystemCall(syscallUUID, -1);

	//Check if INADDR_ANY is already using the port
  iter2 = pid_sockfd_by_ip_port.find(std::pair<in_addr_t, in_port_t>(0, port));
	if (iter2 != pid_sockfd_by_ip_port.end())
    this->returnSystemCall(syscallUUID, -1);

  auto &s = iter->second;

  s.isBound = true;
  s.ip = ip;
  s.port = port;
  s.addr = *addr;
  s.addrlen = addrlen;

  pid_sockfd_by_ip_port[std::pair<in_addr_t, in_port_t>(ip, port)] = {pid, sockfd};

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  if(FUNCTION_LOG) {
    printf("(pid: %d) syscall_getsockname\n", pid);
  }

  auto iter = sockets.find({pid, sockfd});
  // Error: No sockets found
	if(iter == sockets.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
  // Error: Socket is not bound
	if(!(iter->second.isBound))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

  auto &s = iter->second;

  *addr = s.addr;
  *addrlen = s.addrlen;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &s = sockets[{pid, sockfd}];
  *addr = s.remote_addr;
  *addrlen = sizeof(s.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

/* Packet Handling Functions */
void TCPAssignment::manage_init(Packet *packet, Socket *socket)
{
  if(STATE_LOG)
  {
    printf("manage_init\n");
  }
  return;
}

void TCPAssignment::manage_listen(Packet *packet, Socket *socket)
{
  if(STATE_LOG)
  {
    printf("manage_listen\n");
  }
  DataInfo received_info;
  read_packet_header(packet, &received_info);
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t flag = received_info.flag;
  uint32_t seq_num = received_info.seq_num;
  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(received_info.remote_addr);

  if(!(flag & SYN)) return;

  DataInfo info;
  info.local_addr = unit_addr(local_ip, local_port);
  info.remote_addr = unit_addr(remote_ip, remote_port);
  info.seq_num = rand(); info.ack_num = seq_num + 1;
  info.flag = SYN | ACK;

  Packet new_packet(HEADER_SIZE);
  write_packet_header(&new_packet, &info);
  data_infos[{socket->pid, socket->fd}] = info;
  sendPacket("IPv4", std::move(new_packet));

  socket->state = SYN_RCVD_STATE;

  return;
}

void TCPAssignment::manage_synsent(Packet *packet, Socket *socket)
{
  if(STATE_LOG)
  {
    printf("manage_synsent\n");
  }
  DataInfo received_info;
  read_packet_header(packet, &received_info);
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t flag = received_info.flag;
  uint32_t seq_num = received_info.seq_num;
  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(received_info.remote_addr);

  // TODO: Remove duplicatation in code
  if(flag & SYN)
  {
    DataInfo info;
    info.local_addr = unit_addr(local_ip, local_port);
    info.remote_addr = unit_addr(remote_ip, remote_port);
    info.seq_num = seq_num + 1; info.ack_num = seq_num + 1;
    info.flag = ACK;

    Packet new_packet(HEADER_SIZE);
    write_packet_header(&new_packet, &info);
    sendPacket("IPv4", std::move(new_packet));

    if(flag & ACK) socket->state = ESTAB_STATE;
    else socket->state = SYN_RCVD_STATE;

    auto iter = blocked_process_table.find(socket->pid);
    assert(iter != blocked_process_table.end());

    auto &process = iter->second;
    this->returnSystemCall(process.syscallUUID, 0);
    blocked_process_table.erase(socket->pid);
  }
  else {
    assert(0);
  }


  return;
}

void TCPAssignment::manage_synrcvd(Packet *packet, Socket *socket)
{
  if(STATE_LOG)
  {
    printf("manage_synrcvd\n");
  }
  DataInfo received_info;
  read_packet_header(packet, &received_info);
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t flag = received_info.flag;
  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(received_info.remote_addr);

  if(flag & SYN) {
    if (socket->listenQueue->size() + 1 < socket->backlog) {
      Packet clone_packet = *packet;
      socket->listenQueue->push(clone_packet);
    }
    return;
  }

  auto info_it = data_infos.find({socket->pid, socket->fd});
  assert(info_it != data_infos.end());

  auto &info = info_it->second;

  in_addr_t temp_local_ip, temp_remote_ip;
  in_port_t temp_local_port, temp_remote_port;
  std::tie(temp_local_ip, temp_local_port) = divide_addr(info.local_addr);
  std::tie(temp_remote_ip, temp_remote_port) = divide_addr(info.remote_addr);

  if(temp_local_ip != local_ip || temp_remote_ip != remote_ip ||
    temp_local_port != local_port || temp_remote_port != remote_port) {
      return;
  }

  if(!(flag & ACK)) return;

  auto iter = blocked_process_table.find(socket->pid);
  if(iter != blocked_process_table.end()) {
    auto &process = iter->second;
    int new_fd = this->createFileDescriptor(socket->pid);
    assert(new_fd >= 0);

    Socket new_socket;
    std::tie(new_socket.ip, new_socket.port) = divide_addr(info.local_addr);
    new_socket.addr = info.local_addr;
    new_socket.addrlen = sizeof(info.local_addr);
    new_socket.isBound = true;
    new_socket.state = ESTAB_STATE;
    new_socket.receive_buffer = (char *) malloc(RECEIVE_BUFFER_SIZE * sizeof(char));
    new_socket.send_buffer = (char *) malloc(SEND_BUFFER_SIZE * sizeof(char));
    new_socket.is_rcvd_data = false;
    new_socket.data_ptr = new_socket.receive_buffer;
    new_socket.packet_ptr = new_socket.receive_buffer;
    new_socket.remaining = 0;
    new_socket.window = 51200;
    new_socket.seq_num = 1;
    new_socket.send_ptr = new_socket.send_buffer;
    new_socket.ack_ptr = new_socket.send_buffer;

    *process.addr = info.local_addr;
    *process.addrlen = sizeof(info.local_addr);

    new_socket.local_addr = info.local_addr;
    new_socket.remote_addr = info.remote_addr;
    estab_pid_sockfd_by_ip_port[{new_socket.ip, new_socket.port}] = {socket->pid, new_fd};
    sockets[{socket->pid, new_fd}] = new_socket;

    this->returnSystemCall(process.syscallUUID, new_fd);
    blocked_process_table.erase(socket->pid);
  }
  else {
    socket->acceptQueue->push(info);
  }

  socket->state = LISTEN_STATE;
  if(socket->listenQueue->empty()) {
    return;
  }

  // Get a packet from listenQueue
  Packet const& resend_packet = socket->listenQueue->front();
  Packet clone_packet = resend_packet;
  socket->listenQueue->pop();
  packetArrived("IPv4", std::move(clone_packet));

  return;
}

void TCPAssignment::manage_estab(Packet *packet, Socket *socket)
{
  if(STATE_LOG)
  {
    printf("manage_estab\n");
  }
  DataInfo received_info;
  read_packet_header(packet, &received_info);
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint32_t seq_num = received_info.seq_num;
  uint32_t ack_num = received_info.ack_num;
  uint8_t data_ofs = received_info.data_ofs;
  uint16_t total_length = received_info.total_length;
  uint8_t ihl = received_info.ihl;

  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(received_info.remote_addr);

  socket->remote_addr = received_info.remote_addr;
  socket->local_addr = received_info.local_addr;

  uint16_t data_length = total_length - (ihl + data_ofs) * 4;
  int data_start = TCP_START + data_ofs * 4;

  // Handle data packet
  if(data_length != 0)
  {
    // (1) Copy the payload
    for(int i=0; i<data_length; i++) {
      packet->readData(data_start + i, socket->packet_ptr + i, 1);
    }
    // TODO: what if packet_ptr go over receive_buffer?
    socket->packet_ptr += data_length;
    socket->remaining += data_length;

    auto iter = blocked_io_table.find({socket->pid, socket->fd});
    if (iter != blocked_io_table.end()) {
      auto &p = iter->second;

      if(p.count < data_length)
        socket->is_rcvd_data = true;

      size_t read_byte = p.count > data_length ? data_length : p.count;

      // What if buffer size is smaller than p.count?
      memcpy(p.buf, socket->data_ptr, read_byte);
      socket->data_ptr += read_byte;
      socket->remaining -= read_byte;
      this->returnSystemCall(p.syscallUUID, read_byte);
    }

    // (2) Acknowledge received packet
    DataInfo info;
    info.local_addr = unit_addr(local_ip, local_port);
    info.remote_addr = unit_addr(remote_ip, remote_port);
    info.seq_num = ack_num; info.ack_num = seq_num + data_length;
    info.flag = ACK;

    Packet new_packet(HEADER_SIZE);
    write_packet_header(&new_packet, &info);
    sendPacket("IPv4", std::move(new_packet));
  }
  // Handle ACK packet
  else
  {
    // (1) free the send buffer space allocated for acked data

    // (2) move the sender window (the number of in-flight bytes should be decreased)

    // (3) adjust the sender window size (from advertised receive buffer size)

    // (4) send data if there is waiting data in the send buffer and if the data is sendable (i.e., there is room in sender’s window)
  }

  return;
}

void TCPAssignment::manage_fin(Packet *packet, Socket *socket)
{
  return;
}

/* Utility Functions For Packet Manipulation */
std::pair<in_addr_t, in_port_t> TCPAssignment::divide_addr(sockaddr addr)
{
  in_addr_t ip;
  in_port_t port;
  ip = ntohl(((sockaddr_in *)&addr)->sin_addr.s_addr);
  port = ntohs(((sockaddr_in *)&addr)->sin_port);
	return {ip, port};
}

sockaddr TCPAssignment::unit_addr(in_addr_t ip, in_port_t port)
{
  struct sockaddr_in addr_unit;
	memset(&addr_unit, 0, sizeof(struct sockaddr_in));
	addr_unit.sin_family = AF_INET;
  addr_unit.sin_addr.s_addr = htonl(ip);
	addr_unit.sin_port = htons(port);
  struct sockaddr *addr_cast = (struct sockaddr *)(&addr_unit);
	return *addr_cast;
}

void TCPAssignment::read_packet_header(Packet *packet, DataInfo *info)
{
  uint32_t ip_msg, remote_ip_msg, seq_num_msg, ack_num_msg;
	uint16_t port_msg, remote_port_msg, total_length;
  uint8_t flag_msg, ihl, data_ofs;
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;

  packet->readData(IP_START, &ihl, 1);
  packet->readData(IP_START + 2, &total_length, 2);
  packet->readData(IP_START + 12, &remote_ip_msg, 4);
  packet->readData(IP_START + 16, &ip_msg, 4);
	packet->readData(TCP_START + 0, &remote_port_msg, 2);
  packet->readData(TCP_START + 2, &port_msg, 2);
  packet->readData(TCP_START + 4, &seq_num_msg, 4);
  packet->readData(TCP_START + 8, &ack_num_msg, 4);
	packet->readData(TCP_START + 12, &data_ofs, 1);
	packet->readData(TCP_START + 13, &flag_msg, 1);

  ihl = ihl & 15;
  total_length = ntohs(total_length);
  data_ofs = data_ofs >> 4;

  local_ip = (in_addr_t) ntohl(ip_msg); local_port = (in_port_t)ntohs(port_msg);
  remote_ip = (in_addr_t) ntohl(remote_ip_msg); remote_port = (in_port_t) ntohs(remote_port_msg);

  info->local_addr = unit_addr(local_ip, local_port);
  info->remote_addr = unit_addr(remote_ip, remote_port);
  info->seq_num = ntohl(seq_num_msg);
	info->ack_num = ntohl(ack_num_msg);
  info->ihl = ihl;
  info->total_length = total_length;
  info->data_ofs = data_ofs;
  info->flag = flag_msg;

  return;
}

void TCPAssignment::write_packet_header(Packet *new_packet, DataInfo *info)
{
  uint32_t ip_msg, remote_ip_msg, seq_num, ack_num;
	uint16_t port_msg, remote_port_msg, checksum, checksum_converted;
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t tcp_data[DATA_OFS];
  uint8_t header_length = 80;
	uint16_t window = htons(51200);

  std::tie(local_ip, local_port) = divide_addr(info->local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(info->remote_addr);
  ip_msg = htonl(local_ip); port_msg = htons(local_port);
  remote_ip_msg = htonl(remote_ip); remote_port_msg = htons(remote_port);
  seq_num = htonl(info->seq_num); ack_num = htonl(info->ack_num);

	new_packet->writeData(IP_START + 12, &ip_msg, 4);
	new_packet->writeData(IP_START + 16, &remote_ip_msg, 4);

	new_packet->writeData(TCP_START + 0, &port_msg, 2);
	new_packet->writeData(TCP_START + 2, &remote_port_msg, 2);
  new_packet->writeData(TCP_START + 4, &seq_num, 4);
  new_packet->writeData(TCP_START + 8, &ack_num, 4);
	new_packet->writeData(TCP_START + 12, &header_length, 1);
  new_packet->writeData(TCP_START + 13, &(info->flag), 1);
	new_packet->writeData(TCP_START + 14, &window, 2);

  // Checksum Calculation
  new_packet->readData(TCP_START, tcp_data, DATA_OFS);
  checksum = ~ NetworkUtil::tcp_sum(ip_msg, remote_ip_msg, tcp_data, DATA_OFS);
  checksum_converted = htons(checksum);
  new_packet->writeData(TCP_START + 16, &checksum_converted, 2);

  return;
}

void TCPAssignment::write_packet_header_mod(Packet *new_packet,
  size_t ip_start, size_t tcp_start,
  in_addr_t local_ip, in_addr_t remote_ip,
  in_port_t local_port, in_port_t remote_port)
{
  uint32_t ip_msg;
	uint16_t port_msg;
  ip_msg = htonl(local_ip);
	new_packet->writeData(ip_start + 12, &ip_msg, 4);
	ip_msg = htonl(remote_ip);
	new_packet->writeData(ip_start + 16, &ip_msg, 4);

	port_msg = htons(local_port);
	new_packet->writeData(tcp_start + 0, &port_msg, 2);
	port_msg = htons(remote_port);
	new_packet->writeData(tcp_start + 2, &port_msg, 2);

  // Can new_data_ofs_ns and window_size change?
	uint8_t data_ofs = DATA_OFS;
	uint16_t window = htons(51200);
	new_packet->writeData(tcp_start + 12, &data_ofs, 1);
	new_packet->writeData(tcp_start + 14, &window, 2);

  return;
}


} // namespace E
