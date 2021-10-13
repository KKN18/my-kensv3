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

#define LOG 0
#define LOG2 0
#define IP_START 14
#define TCP_START 34
#define HEADER_SIZE 54
#define WINDOW_SIZE 51200
#define DATA_OFS 20

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
  if(LOG) {
    printf("(pid: %d) systemCallback\n", pid);
  }

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
  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;
  uint8_t flag = received_info.flag;
  uint32_t seq_num = received_info.seq_num;
  uint32_t ack_num = received_info.ack_num;
  uint8_t header_length = received_info.header_length;

  std::tie(local_ip, local_port) = divide_addr(received_info.local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(received_info.remote_addr);

  auto iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(0, local_port));
  if(iter == pid_sockfd_by_ip_port.end())
  {
      iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, in_port_t>(local_ip, local_port));
      if (iter == pid_sockfd_by_ip_port.end())
      {
        return;
      }
  }

  int pid, fd;
  pid = iter->second.first;
  fd = iter->second.second;

  auto iter2 = sockets.find({pid, fd});
  if(LOG2)
  {
    printf("   sockets.find({%d %d})\n", pid, fd);
  }

  if(iter2 == sockets.end()){
    // Error: Socket not found
    // Not sure
    return;
  }

  auto &s = iter2->second;

  assert(pid == s.pid);

  /* Write Packet START */
	Packet new_packet(HEADER_SIZE);
  write_packet_header_mod(&new_packet, &received_info);

	switch(s.state)
	{
		case INIT_STATE:
      if(LOG)
      {
        printf("  Server's state is ST_READY\n");
      }
			break;

		case LISTEN_STATE:	{
      if(LOG)
      {
        printf("  Server's state is ST_LISTEN\n");
      }

			if(flag & SYN)
			{
        DataInfo info;
        info.local_ip = local_ip; info.local_port = local_port;
        // TODO: Remove duplicate elements
        info.local_addr = unit_addr(local_ip, local_port);
        info.remote_ip = remote_ip; info.remote_port = remote_port;
        info.remote_addr = unit_addr(remote_ip, remote_port);
        info.seq_num = rand(); info.ack_num = seq_num + 1;
        info.flag = SYN | ACK;

        write_packet_response_mod(&new_packet, &info, &received_info);

        data_infos[{pid, fd}] = info;

				sendPacket("IPv4", std::move(new_packet));

				s.state = SYN_RCVD_STATE;
			}
			break;
    }

		case SYN_SENT_STATE: {
      if(LOG)
        {
          printf("  Client's state is ST_SYN_SENT\n");
        }

  			if((flag & SYN) && (flag & ACK))
  			{
          if(LOG)
          {
            printf("  Client's state is ST_SYN_SENT\n");
          }

          DataInfo info;
          info.local_ip = local_ip; info.local_port = local_port;
          // TODO: Remove duplicate elements
          info.local_addr = unit_addr(local_ip, local_port);
          info.remote_ip = remote_ip; info.remote_port = remote_port;
          info.remote_addr = unit_addr(remote_ip, remote_port);
          info.seq_num = seq_num + 1; info.ack_num = seq_num + 1;
          info.flag = ACK;

          write_packet_response_mod(&new_packet, &info, &received_info);

  				sendPacket("IPv4", std::move(new_packet));

  				s.state = ESTAB_STATE;

          auto iter = blocked_process_table.find(pid);
          if (iter != blocked_process_table.end()) {
            auto &process = iter->second;
						this->returnSystemCall(process.syscallUUID, 0);
            blocked_process_table.erase(pid);
        }
        else {
          assert(0);
        }
			}
			else if(flag & SYN)
      {
        DataInfo info;
        info.local_ip = local_ip; info.local_port = local_port;
        // TODO: Remove duplicate elements
        info.local_addr = unit_addr(local_ip, local_port);
        info.remote_ip = remote_ip; info.remote_port = remote_port;
        info.remote_addr = unit_addr(remote_ip, remote_port);
        info.seq_num = seq_num + 1; info.ack_num = seq_num + 1;
        info.flag = ACK;

        write_packet_response_mod(&new_packet, &info, &received_info);

        sendPacket("IPv4", std::move(new_packet));

        s.state = SYN_RCVD_STATE;

        auto iter = blocked_process_table.find(pid);
        if (iter != blocked_process_table.end()) {
          auto &process = iter->second;
          this->returnSystemCall(process.syscallUUID, 0);
          blocked_process_table.erase(pid);
      }
    }
    }
      break;


		case SYN_RCVD_STATE: {
      if(LOG)
      {
        printf("  Server's state is ST_SYN_RCVD\n");
      }

      if(flag & SYN)
      {
        if (s.listenQueue->size() + 1 < s.backlog){
          Packet clone_packet = packet;
          s.listenQueue->push(clone_packet);
        }
        if(LOG)
        {
          printf("  Currently working on another socket... Put in Queue\n");
          printf("  Listen Queue Size: %d\n", s.listenQueue->size());
        }

        return;
        break;
      }

      auto info_it = data_infos.find({pid, fd});

      if (info_it == data_infos.end())
      {
        // TODO: Not sure
        return;
      }

      auto &info = info_it->second;

      in_addr_t temp_local_ip, temp_remote_ip;
      in_port_t temp_local_port, temp_remote_port;

      std::tie(temp_local_ip, temp_local_port) = divide_addr(info.local_addr);
      std::tie(temp_remote_ip, temp_remote_port) = divide_addr(info.remote_addr);

      if(temp_local_ip == local_ip && temp_local_port == local_port &&
        temp_remote_ip == remote_ip && temp_remote_port == remote_port)
			{

        if(flag & ACK)
        {
          if(LOG)
          {
            printf("  Accepting this packet... change server state to ST_LISTEN.\n");
          }

          auto iter = blocked_process_table.find(pid);
          if (iter != blocked_process_table.end()) {

            auto &process = iter->second;

						int new_fd = this->createFileDescriptor(pid);
            if(new_fd < 0)
            {
              // Error: File Descriptor not created!
              return;
            }

            Socket new_socket;
            std::tie(new_socket.ip, new_socket.port) = divide_addr(info.local_addr);
            new_socket.addr = info.local_addr;
            new_socket.addrlen = sizeof(info.local_addr);
            new_socket.isBound = true;
            new_socket.state = ESTAB_STATE;

            *process.addr = info.local_addr;
            *process.addrlen = sizeof(info.local_addr);

            sockets[{pid, new_fd}] = new_socket;

						this->returnSystemCall(process.syscallUUID, new_fd);
            blocked_process_table.erase(pid);
        }
        else {
          s.acceptQueue->push(info);
        }

        s.state = LISTEN_STATE;
        if(s.listenQueue->empty()) {
          return;
        }

        // Get a packet from listenQueue
        Packet const& resend_packet = s.listenQueue->front();
        Packet clone_packet = resend_packet;
        s.listenQueue->pop();
        packetArrived("IPv4", std::move(clone_packet));

        return;
        }
      }
    }
      break;

    case ESTAB_STATE:
      break;

		default:
			assert(0);
	}
}

void TCPAssignment::timerCallback(std::any payload) {
  if(LOG) {
    printf("timerCallback\n");
  }
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
  if(LOG) {
    printf("(pid: %d) syscall_socket\n", pid);
  }

	assert(domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP);
  if(domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
    errno = EACCES;
    this->returnSystemCall(syscallUUID, -1);
  }

	int fd = this->createFileDescriptor(pid);
  if (fd < 0)
    return;

  Socket s;
  s.pid = pid;
  s.fd = fd;
  s.type = type;
  s.protocol = protocol;
  s.isBound = false;
  s.state = INIT_STATE;

  sockets[{pid, fd}] = s;

	this->returnSystemCall(syscallUUID, fd);
}

/*
The close() call receives a parameter from the application layer. It closes the file descriptor’s
connection and deallocates the file descriptor. More details about the socket call are
described https://linux.die.net/man/2/close and https://linux.die.net/man/3/close.
*/
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
  if(LOG) {
    printf("(pid: %d) syscall_close\n", pid);
  }
  auto iter = sockets.find({pid, fd});

  if(iter != sockets.end())
  {
    auto &s = iter->second;

    in_addr_t ip;
    in_port_t port;

    ip = s.ip;
    port = s.port;
    sockets.erase(iter);
    pid_sockfd_by_ip_port.erase(std::pair<in_addr_t, in_port_t>(ip, port));
  }

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

/*
The connect() call receives 3 parameters from the application layer. It connects the file
descriptor to the address specified by addr. More details about the socket call are described
https://linux.die.net/man/2/connect and https://linux.die.net/man/3/connect.
*/
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  if(LOG2) {
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

  in_addr_t remote_ip, local_ip;
  in_port_t remote_port, local_port;

  std::tie(remote_ip, remote_port) = divide_addr(*addr);

  s.client_info.remote_addr = *addr;

  in_addr_t network_remote_ip = htonl(remote_ip);

  char remote_ip_buffer[20];
  inet_ntop(AF_INET, &network_remote_ip, remote_ip_buffer, sizeof(remote_ip_buffer));

  ipv4_t converted_remote_ip;

  sscanf(remote_ip_buffer, "%d.%d.%d.%d", &converted_remote_ip[0],
    &converted_remote_ip[1], &converted_remote_ip[2], &converted_remote_ip[3]);

  if (!s.isBound){

  	int table_port = getRoutingTable(converted_remote_ip);
    printf("TABLE_PORT: %d\n", table_port);

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
    // Not Sure
    s.addrlen = sizeof(s.addr);
  }
  else {
    local_ip = s.ip;
    local_port = s.port;
  }
  in_addr_t local_ip_converted = htonl(local_ip);
  in_addr_t remote_ip_converted = htonl(remote_ip);
  Packet packet(HEADER_SIZE);

  /* Writing Packet */
  uint32_t rand_num = rand();
  uint32_t seq_num = htonl(rand_num);
  uint8_t flag = SYN;
  packet.writeData(TCP_START + 4, &seq_num, 4);
  packet.writeData(TCP_START + 13, &flag, 1);
  write_packet_header(&packet, IP_START, TCP_START, local_ip,
    remote_ip, local_port, remote_port);

  uint8_t buffer[DATA_OFS];
  packet.readData(TCP_START, buffer, DATA_OFS);

  uint16_t checksum = ~NetworkUtil::tcp_sum(local_ip_converted, remote_ip_converted, buffer, DATA_OFS);
  uint16_t checksum_converted = htons(checksum);
  packet.writeData(TCP_START + 16, &checksum_converted, 2);
  /* Writing packet finished */

  sendPacket("IPv4", std::move(packet));
  s.state = SYN_SENT_STATE;
  return;
}

/*
The listen() call receives 2 parameters from the application layer. It marks the socket as a
passive socket, that is, as a socket that will be used to accept incoming connection requests
using accept. KENS requires you to implement the backlog parameter. It defines the
maximum length to which the queue of pending connections for sockfd may grow. More
details about the socket call are described https://linux.die.net/man/2/listen and
https://linux.die.net/man/3/listen.
*/
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
  if(LOG) {
    printf("(pid: %d) syscall_listen\n", pid);
  }
	auto sock_it = sockets.find({pid, sockfd});

	if(sock_it == sockets.end()) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

  if(sock_it->second.isBound == false) {
    this->returnSystemCall(syscallUUID, -1);
		return;
  }

  if(backlog > 128 || backlog <= 0)
  {
    if(LOG)
    {
      printf("Unexpected backlog value");
    }
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto &s = sock_it->second;

	s.state = LISTEN_STATE;
  s.listenQueue = new std::queue<Packet>;
  s.acceptQueue = new std::queue<DataInfo>;
  s.backlog = (unsigned int) backlog;

  this->returnSystemCall(syscallUUID, 0);
}

/*
The accept() call receives 3 parameters from the application layer. It extracts the first
connection on the queue of pending connections. It creates and returns a new file descriptor
for the connection. It also fills the address parameter with connecting client’s information.
More details about the socket call are described https://linux.die.net/man/2/accept and
https://linux.die.net/man/3/accept .
*/
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  if(LOG) {
    printf("(pid: %d) syscall_accept\n", pid);
  }

  auto sock_it = sockets.find({pid, sockfd});
  if(sock_it == sockets.end())
  {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto &s = sock_it->second;

  int fd = this->createFileDescriptor(pid);

  if (fd < 0)
    return;

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
  *addr = info.local_addr;
  *addrlen = sizeof(*addr);

  sockets[{pid, fd}] = new_socket;

  this->returnSystemCall(syscallUUID, fd);
}

/*
The bind() call receives 3 parameters from the application layer. Now it should assign an
address to the socket. More details about the socket call are described
https://linux.die.net/man/2/bind and https://linux.die.net/man/3/bind .
In KENS, you need to implement only sockaddr_in type for sockaddr.

The only value you should assign to sin_family is AF_INET. The two fields, sin_port and
sin_addr, must follow the network byte order. The sin_addr field must be either an IP
address or INADDR_ANY. You should implement both cases.
*/
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

  if(LOG) {
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
  if(LOG) {
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

/*
getpeername() returns the address of the peer connected to the
socket sockfd, in the buffer pointed to by addr.  The addrlen
argument should be initialized to indicate the amount of space
pointed to by addr.  On return it contains the actual size of the
name returned (in bytes).  The name is truncated if the buffer
provided is too small.

The returned address is truncated if the buffer provided is too
small; in this case, addrlen will return a value greater than was
supplied to the call.
*/
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &s = sockets[{pid, sockfd}];
  *addr = s.client_info.remote_addr;
  *addrlen = (socklen_t)sizeof(s.client_info.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

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
  sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);
	return *(sockaddr *)(&addr);
}

void TCPAssignment::read_packet_header(Packet *packet, DataInfo *info)
{
  uint32_t ip_msg;
	uint16_t port_msg;
  uint32_t seq_num_msg;
  uint32_t ack_num_msg;
  uint8_t header_length_msg;
  uint8_t flag_msg;

  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;

  packet->readData(IP_START + 12, &ip_msg, 4);
	packet->readData(TCP_START + 0, &port_msg, 2);
  remote_ip = (in_addr_t)ntohl(ip_msg);
  remote_port = (in_port_t)ntohs(port_msg);

  info->remote_addr = unit_addr(remote_ip, remote_port);

  packet->readData(IP_START + 16, &ip_msg, 4);
	packet->readData(TCP_START + 2, &port_msg, 2);
  local_ip = (in_addr_t)ntohl(ip_msg);
  local_port = (in_port_t)ntohs(port_msg);

  info->local_addr = unit_addr(local_ip, local_port);

  packet->readData(TCP_START + 4, &seq_num_msg, 4);
  info->seq_num = ntohl(seq_num_msg);

	packet->readData(TCP_START + 8, &ack_num_msg, 4);
	info->ack_num = ntohl(ack_num_msg);

	packet->readData(TCP_START + 12, &header_length_msg, 1);
  info->header_length = header_length_msg;

	packet->readData(TCP_START + 13, &flag_msg, 1);
  info->flag = flag_msg;

  return;
}

void TCPAssignment::write_packet_response(Packet *new_packet,
  size_t ip_start, size_t tcp_start,
  uint8_t new_flag, uint32_t new_seq_num, uint32_t new_ack_num,
  in_addr_t local_ip, in_addr_t remote_ip)
{
  uint8_t tcp_data[DATA_OFS];
	uint16_t checksum;

  new_packet->writeData(tcp_start + 4, &new_seq_num, 4);
  new_packet->writeData(tcp_start + 8, &new_ack_num, 4);
  new_packet->writeData(tcp_start + 13, &new_flag, 1);

  new_packet->readData(tcp_start, tcp_data, DATA_OFS);
  checksum = ~NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_data, DATA_OFS);
  uint16_t checksum_converted = htons(checksum);
  new_packet->writeData(tcp_start + 16, &checksum_converted, 2);

  return;
}

void TCPAssignment::write_packet_header(Packet *new_packet,
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

void TCPAssignment::write_packet_header_mod(Packet *new_packet, DataInfo *info)
{
  uint32_t ip_msg;
	uint16_t port_msg;

  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;

  std::tie(local_ip, local_port) = divide_addr(info->local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(info->remote_addr);

  ip_msg = htonl(local_ip);
	new_packet->writeData(IP_START + 12, &ip_msg, 4);
	ip_msg = htonl(remote_ip);
	new_packet->writeData(IP_START + 16, &ip_msg, 4);

	port_msg = htons(local_port);
	new_packet->writeData(TCP_START + 0, &port_msg, 2);
	port_msg = htons(remote_port);
	new_packet->writeData(TCP_START + 2, &port_msg, 2);

	uint8_t header_length = 80;
	uint16_t window = htons(51200);
	new_packet->writeData(TCP_START + 12, &header_length, 1);
	new_packet->writeData(TCP_START + 14, &window, 2);

  return;
}

void TCPAssignment::write_packet_response_mod(Packet *new_packet, DataInfo *send_info, DataInfo *received_info)
{
  uint8_t tcp_data[DATA_OFS];
	uint16_t checksum;
  uint32_t seq_num, ack_num;

  seq_num = htonl(send_info->seq_num);
  ack_num = htonl(send_info->ack_num);

  new_packet->writeData(TCP_START + 4, &seq_num, 4);
  new_packet->writeData(TCP_START + 8, &ack_num, 4);
  new_packet->writeData(TCP_START + 13, &(send_info->flag), 1);

  new_packet->readData(TCP_START, tcp_data, DATA_OFS);

  in_addr_t local_ip, remote_ip;
  in_port_t local_port, remote_port;

  std::tie(local_ip, local_port) = divide_addr(send_info->local_addr);
  std::tie(remote_ip, remote_port) = divide_addr(send_info->remote_addr);

  local_ip = htonl(local_ip);
  remote_ip = htonl(remote_ip);

  checksum = ~ NetworkUtil::tcp_sum(local_ip, remote_ip, tcp_data, DATA_OFS);
  uint16_t checksum_converted = htons(checksum);
  new_packet->writeData(TCP_START + 16, &checksum_converted, 2);

  return;
}



} // namespace E
