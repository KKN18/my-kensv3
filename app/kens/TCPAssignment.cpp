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

#define FUNCTION_LOG 0
#define LOG 0
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

  auto iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(0, local_port));
  if(iter == pid_sockfd_by_ip_port.end())
  {
      iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(local_ip, local_port));
      if (iter == pid_sockfd_by_ip_port.end())
      {
        return;
        // assert(0);
      }
  }

  auto iter2 = sockets.find({iter->second.first, iter->second.second});
  assert(iter2 != sockets.end());

  auto &s = iter2->second;
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
    // printf("(pid: %d) syscall_read\n", pid);
  }
  Socket s = sockets[{pid, fd}];
  if (s.is_rcvd_data){
      memcpy(buf, s.receive_buffer, count);
      this->returnSystemCall(syscallUUID, fd);
      return count;
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

  // Socket s = sockets[{pid, fd}];
  // if(s.enough_send_space)
  // {
  //   // if(data lies in sender window)
  // }
  // else
  // {
  //
  // }
  // return;
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
  s.receive_ptr = s.receive_buffer;

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
  assert(iter != sockets.end());

  Process p;
  p.syscallUUID = syscallUUID;
  blocked_process_table[pid] = p;

  auto &s = iter->second;
  s.connect_addr = *addr;

  in_addr_t remote_ip, local_ip;
  in_port_t remote_port, local_port;

  char local_ip_buffer[20];
  char remote_ip_buffer[20];

  std::tie(remote_ip, remote_port) = divide_addr(*addr);

  in_addr_t network_remote_ip = htonl(remote_ip);

  // in_addr_t to char[] conversion
  inet_ntop(AF_INET, &network_remote_ip, remote_ip_buffer, sizeof(remote_ip_buffer));

  // char[] to ipv4_t conversion
  ipv4_t converted_remote_ip;
  sscanf(remote_ip_buffer, "%c.%c.%c.%c", &converted_remote_ip[0],
    &converted_remote_ip[1], &converted_remote_ip[2], &converted_remote_ip[3]);

  if (!s.isBound) {
  	int table_port = getRoutingTable(converted_remote_ip);
    std::optional<ipv4_t> local_ip_array = getIPAddr(table_port);
    assert(local_ip_array.has_value() == true);

    // ipv4_t to char[] conversion
    for (int i=3; i>=0; i--) {
      std::string buf = std::to_string((*local_ip_array)[i]);
      strcat(local_ip_buffer, buf.c_str());
      if(i != 0)
        strcat(local_ip_buffer, ".");
    }

    // char[] to in_addr_t conversion
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

  /* Writing Packet */
  DataInfo send_info;

  send_info.local_addr = unit_addr(local_ip, local_port);
  send_info.seq_num = htonl(rand());
  // TODO: Not sure about ack_num and header_length
  send_info.ack_num = 1;
  send_info.header_length = 80;
  send_info.flag = SYN;

  Packet packet(HEADER_SIZE);
  write_packet_header(&packet, &send_info);
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
  *addr = info.local_addr;
  *addrlen = sizeof(*addr);

  sockets[{pid, fd}] = new_socket;

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
  *addr = s.connect_addr;
  *addrlen = sizeof(s.connect_addr);
	this->returnSystemCall(syscallUUID, 0);
}

/* Packet Handling Functions */
void TCPAssignment::manage_init(Packet *packet, Socket *socket)
{
  return;
}

void TCPAssignment::manage_listen(Packet *packet, Socket *socket)
{
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

  return;
}

void TCPAssignment::manage_synrcvd(Packet *packet, Socket *socket)
{
  DataInfo received_info;
  read_packet_header(packet, &received_info);
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t flag = received_info.flag;
  uint32_t seq_num = received_info.seq_num;
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

  if(flag & ACK) {
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

      *process.addr = info.local_addr;
      *process.addrlen = sizeof(info.local_addr);

      sockets[{socket->pid, new_fd}] = new_socket;

      this->returnSystemCall(process.syscallUUID, new_fd);
      blocked_process_table.erase(socket->pid);
    }
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
	uint16_t port_msg, remote_port_msg;
  uint8_t header_length_msg, flag_msg;
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;

  packet->readData(IP_START + 12, &remote_ip_msg, 4);
  packet->readData(IP_START + 16, &ip_msg, 4);
	packet->readData(TCP_START + 0, &remote_port_msg, 2);
  packet->readData(TCP_START + 2, &port_msg, 2);
  packet->readData(TCP_START + 4, &seq_num_msg, 4);
  packet->readData(TCP_START + 8, &ack_num_msg, 4);
	packet->readData(TCP_START + 12, &header_length_msg, 1);
	packet->readData(TCP_START + 13, &flag_msg, 1);

  local_ip = (in_addr_t)ntohl(ip_msg); local_port = (in_port_t)ntohs(port_msg);
  remote_ip = (in_addr_t) ntohl(remote_ip_msg); remote_port = (in_port_t) ntohs(remote_port_msg);

  info->local_addr = unit_addr(local_ip, local_port);
  info->remote_addr = unit_addr(remote_ip, remote_port);
  info->seq_num = ntohl(seq_num_msg);
	info->ack_num = ntohl(ack_num_msg);
  info->header_length = header_length_msg;
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

} // namespace E
