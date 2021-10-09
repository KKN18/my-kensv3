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

#define LOG 1

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
	/* Packet arrived from IPv4 Module!
	 * (1) Read from packet local and remote addresses.
	 * (2) Forward the packet to corresponding TCPSocket.
	 * (3) Handle the packet according to the state of the socket.
	 */

	const size_t ip_start = 14;  /* Size of Ethernet header */

	uint8_t ihl_buffer;
	packet.readData(ip_start, &ihl_buffer, 1);
	size_t ihl = (ihl_buffer & 0x0f) * 4;  /* Size of the IP header */

	size_t tcp_start = ip_start + ihl;
	uint32_t ip_buffer;
	uint16_t port_buffer;

	packet.readData(ip_start + 12, &ip_buffer, 4);
	packet.readData(tcp_start + 0, &port_buffer, 2);
	in_addr_t remote_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t remote_port = (in_port_t)ntohs(port_buffer);
	// sockaddr remote_addr = tie_addr(remote_ip, remote_port);

	packet.readData(ip_start + 16, &ip_buffer, 4);
	packet.readData(tcp_start + 2, &port_buffer, 2);
	in_addr_t local_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t local_port = (in_port_t)ntohs(port_buffer);
	// sockaddr local_addr = tie_addr(local_ip, local_port);
  /* Read Packet FINISH */
  if(LOG) {
    char local_ip_buffer[20];
    char remote_ip_buffer[20];

    inet_ntop(AF_INET, &local_ip, local_ip_buffer, sizeof(local_ip_buffer));
    inet_ntop(AF_INET, &remote_ip, remote_ip_buffer, sizeof(remote_ip_buffer));

    printf("  local_ip: %s\n", local_ip_buffer);
    printf("  local_port: %d\n", local_port);
    printf("  remote_ip: %s\n", remote_ip_buffer);
    printf("  remote_port: %d\n", remote_port);
  }

  auto test_iter = pid_sockfd_by_ip_port.begin();
  if(LOG) {
    printf("  <Start iterating>\n");
  }
  for (test_iter; test_iter != pid_sockfd_by_ip_port.end(); test_iter++) {
    if(LOG)
    {
      printf("   ip %d port %d\n", test_iter->first.first, test_iter->first.second);
      printf("   pid %d sockfd %d\n", test_iter->second.first, test_iter->second.second);
    }
  }

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
  if(LOG)
  {
    printf("   sockets.find({%d %d})\n", pid, fd);
  }

  if(iter2 == sockets.end()){
    // Error: Socket not found
    // Not sure
    // this->freePacket(packet);
    return;
  }

  auto &s = iter2 ->second;
  pid = s.pid;

	// std::tie(pid, fd) = addr_sock_it->second;
	// auto &pcb = proc_table[pid];
	// auto &sock = pcb.fd_info[fd];

  /* Read Packet START AGAIN */
	uint32_t seq_num;
	packet.readData(tcp_start + 4, &seq_num, 4);
	seq_num = ntohl(seq_num);
	uint32_t ack_num;
	packet.readData(tcp_start + 8, &ack_num, 4);
	ack_num = ntohl(ack_num);

	uint8_t data_ofs_ns;
	packet.readData(tcp_start + 12, &data_ofs_ns, 1);
	size_t data_ofs = (data_ofs_ns >> 4) * 4;

	uint8_t flag;
	packet.readData(tcp_start + 13, &flag, 1);
  /* Read Packet FINISH */
  if(LOG)
  {
    printf("  seq_num: %d\n", seq_num);
    printf("  ack_num: %d\n", ack_num);
    printf("  data_ofs_ns: %d\n", data_ofs_ns);
    printf("  flag: %d\n", flag);
  }

  /* Write Packet START */
	size_t header_size = tcp_start + data_ofs;

	Packet new_packet(header_size);

  // Replace by function call
  write_packet_header(&new_packet, ip_start, tcp_start, local_ip,
    remote_ip, local_port, remote_port);

	uint8_t tcp_header_buffer[20];
	uint16_t checksum;
	uint8_t new_flag;
	uint32_t new_seq_num;
	uint32_t new_ack_num;
  /* Write Packet FINISH */
  if(LOG)
    printf("\n  ======== SERVER ======== \n");

	switch(s.state)
	{
		case ST_READY: 		/* Socket is ready. */
      if(LOG)
      {
        printf("  Server's state is ST_READY\n");
      }
			break;

		case ST_LISTEN:	{	/* Connect ready. Only for server. */
      if(LOG)
      {
        printf("  Server's state is ST_LISTEN\n");
      }
      int current = ST_LISTEN;
			if(flag & SYN)
			{
				new_flag = SYN | ACK;
				new_seq_num = htonl(rand());
				new_ack_num = htonl(seq_num + 1);

        write_packet_response(&new_packet, ip_start, tcp_start, new_flag,
          new_seq_num, new_ack_num, local_ip, remote_ip);

        Context c;
        c.local_ip = local_ip;
        c.local_port = local_port;
        // TODO: Remove duplicate elements
        c.local_addr = tie_addr(local_ip, local_port);
        c.remote_ip = remote_ip;
        c.remote_port = remote_port;
        c.remote_addr = tie_addr(remote_ip, remote_port);
        c.seq_num = ntohl(new_seq_num);
        // TODO: ack num is not touched here?

        contexts[{pid, fd}] = c;

				sendPacket("IPv4", std::move(new_packet));

				s.state = ST_SYN_RCVD;
			}
			break;
    }

		case ST_SYN_SENT:	{/* 3-way handshake, client. */
        if(LOG)
        {
          printf("  Server's state is ST_SYN_SENT\n");
        }
        int current = ST_SYN_SENT;
  			if((flag & SYN) && (flag & ACK))
  			{
          auto context_it = contexts.find({pid, fd});
          if (context_it == contexts.end())
          {
  					// this->returnSystemCall(pcb.syscallUUID, -1);
  					s.state = ST_READY;
  					break;
          }
  				if(ack_num != context_it->second.seq_num + 1)
  				{
  					// this->returnSystemCall(pcb.syscallUUID, -1);
  					s.state = ST_READY;
  					break;
  				}

  				new_flag = ACK;
  				new_packet.writeData(tcp_start + 13, &new_flag, 1);

  				new_ack_num = htonl(seq_num + 1);
  				new_packet.writeData(tcp_start + 8, &new_ack_num, 4);

  				new_packet.readData(tcp_start, tcp_header_buffer, 20);
  				checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
  				checksum = ~checksum;
  				checksum = htons(checksum);
  				new_packet.writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

  				sendPacket("IPv4", std::move(new_packet));

  				s.state = ST_ESTAB;

  				// this->returnSystemCall(pcb.syscallUUID, 0);
			}
			else if(flag & SYN)
				//assert(0);  // Simultaneous open not considered
			break;
    }

		case ST_SYN_RCVD: {	/* 3-way handshake, server. */
      // TODO
      if(LOG)
      {
        printf("  Server's state is ST_SYN_RCVD\n");
      }
      auto context_it = contexts.find({pid, fd});
      int current = ST_SYN_RCVD;
      if (context_it == contexts.end())
      {
        // TODO: Not sure
        return;
      }

      if(flag & SYN)
      {
        if(LOG)
        {
          printf("  Currently working on another socket... Put in Queue\n");
        }
        auto &sock = sockets[{pid, fd}];
        if (sock.listen_queue->size()+1 < sock.backlog){
          Packet clone_packet = packet;
          sock.listen_queue->push(clone_packet);
        }
        if(LOG)
        {
          printf("  Listen Quue Size: %d\n", sock.listen_queue->size());
        }
        break;
      }

      auto &c = context_it->second;
			if( std::make_pair(c.local_ip, c.local_port) == std::make_pair(local_ip, local_port) &&
				std::make_pair(c.remote_ip, c.remote_port) == std::make_pair(remote_ip, remote_port))
			{
				if(flag & ACK)
				{
          if(LOG)
          {
            printf("  Accepting this packet... change server state to ST_LISTEN.\n");
          }
          auto &sock = sockets[{pid, fd}];
          sock.accept_queue->push(c);
          sock.state = ST_LISTEN;
          if (!sock.listen_queue->empty()){
            Packet const& resend_packet = sock.listen_queue->front();
            Packet clone_packet = resend_packet;
						sock.listen_queue->pop();
						packetArrived("IPv4", std::move(clone_packet));
          }
				}
			}
			break;
    }

		case ST_ESTAB:		/* Connection established. */
			//assert(0);  // Read/Write not implemented!
			break;

		case ST_FIN_WAIT_1:	/* 4-way handshake, active close. */
		case ST_FIN_WAIT_2:

		case ST_TIME_WAIT:
		case ST_CLOSE_WAIT:	/* 4-way handshake, passive close. */
		case ST_LAST_ACK:

		case ST_CLOSING:	/* Recieved FIN after sending FIN. */
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
	// assert(domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP);
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
  s.state = ST_READY;

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

    uint32_t ip;
    int port;

    // std::tie(ip, port) = it2->first;
    ip = s.ip;
    port = s.port;
    sockets.erase(iter);
    pid_sockfd_by_ip_port.erase(std::pair<uint32_t, int>(ip, port));
    // TODO: Socket's context also has to be managed here
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
  if(LOG) {
    printf("(pid: %d) syscall_bind\n", pid);
  }
  auto iter = sockets.find({pid, sockfd});
  if(iter == sockets.end()) {
    this->returnSystemCall(syscallUUID, -1);
  }

  auto &s = iter->second;

  in_addr_t remote_ip;
  in_port_t remote_port;

  remote_ip = ntohl(((sockaddr_in *)&addr)->sin_addr.s_addr);
  remote_port = ntohs(((sockaddr_in *)&addr)->sin_port);

  s.client_context.remote_addr = *addr;

  if(s.state != ST_READY) {
    // Error
    return;
  }

  char remote_ip_buffer[20];
  inet_ntop(AF_INET, &remote_ip, remote_ip_buffer, sizeof(remote_ip_buffer));

  char *token = strtok(remote_ip_buffer, ".");
  ipv4_t converted_remote_ip;

  int idx = 0;

  while (token != NULL) {
      // printf("%s\n", token);
      converted_remote_ip[idx++] = atoi(token);
      token = strtok(NULL, ".");
  }

	int table_port = getRoutingTable(converted_remote_ip);
  std::optional<ipv4_t> local_ip_array = getIPAddr(table_port);
  char local_ip_buffer[20];

  for (int i=0; i<4; i++) {
    std::string buf = std::to_string((*local_ip_array)[i] - '0');
    strcat(local_ip_buffer, buf.c_str());
    if(i != 3)
      strcat(local_ip_buffer, ".");
  }

  in_addr_t local_ip;
	in_port_t local_port;

  inet_pton(AF_INET, local_ip_buffer, &local_ip);

  /* Find port that is not taken yet */
	while (true)
	{
		local_port = rand() % 65536;
    if (pid_sockfd_by_ip_port.find({local_ip, local_port}) == pid_sockfd_by_ip_port.end()
          && pid_sockfd_by_ip_port.find({0, local_port}) == pid_sockfd_by_ip_port.end())
			break;
	}

  pid_sockfd_by_ip_port[{local_ip, local_port}] = {pid, sockfd};

  s.ip = local_ip;
  s.port = local_port;
  s.isBound = true;
  s.addr = tie_addr(local_ip, local_port);
  // Not Sure
  s.addrlen = sizeof(struct sockaddr_in);

  size_t ip_start = 14;
  size_t tcp_start = 34;
  size_t data_ofs = 20;

  Packet packet(tcp_start + data_ofs);

  uint32_t ip_buffer = htonl(local_ip);
  packet.writeData(ip_start + 12, &ip_buffer, 4);
  ip_buffer = htonl(remote_ip);
  packet.writeData(ip_start + 16, &ip_buffer, 4);

  uint16_t port_buffer = htons(local_port);
  packet.writeData(tcp_start + 0, &port_buffer, 2);
  port_buffer = htons(remote_port);
  packet.writeData(tcp_start + 2, &port_buffer, 2);

  uint8_t new_data_ofs_ns = 5 << 4;
  uint16_t window_size = htons(51200);
  packet.writeData(tcp_start + 12, &new_data_ofs_ns, 1);
  packet.writeData(tcp_start + 14, &window_size, 2);

  uint8_t flag = SYN;
  packet.writeData(tcp_start + 13, &flag, 1);

  uint32_t seq_num = htonl(rand());
  packet.writeData(tcp_start + 4, &seq_num, 4);

  uint8_t tcp_header_buffer[20];
  packet.readData(tcp_start, tcp_header_buffer, 20);
  uint16_t checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
  checksum = ~checksum;
  checksum = htons( checksum);
  packet.writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

  this->sendPacket("IPv4", std::move(packet));

  s.state = ST_SYN_SENT;
  s.client_context.seq_num = ntohl(seq_num);
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

	if(sock_it == sockets.end() || sock_it->second.isBound == false)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

  auto &s = sock_it->second;

	s.state = ST_LISTEN;

  // TODO: Imeplement backlog
  s.listen_queue = new std::queue<Packet>;
  s.accept_queue = new std::queue<Context>;
  s.backlog = backlog;

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

  return;
  if(LOG) {
    printf("(pid: %d) syscall_accept\n", pid);
  }

  //assert(0);
  auto sock_it = sockets.find({pid, sockfd});
  if(sock_it == sockets.end()
    || (sock_it->second.state != ST_LISTEN
      && sock_it->second.state != ST_SYN_RCVD))
  {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto &s = sock_it->second;

  int connfd = this->createFileDescriptor(pid);

  if (connfd < 0)
    return;

  Context context = s.accept_queue->front();
  s.accept_queue->pop();

  Socket new_socket;
  new_socket.addr = context.remote_addr;
  new_socket.addrlen = sizeof(context.remote_addr);
  new_socket.isBound = true;
  *addr = context.remote_addr;
  *addrlen = sizeof(*addr);

  sockets[{pid, connfd}] = new_socket;

  this->returnSystemCall(syscallUUID, connfd);
}

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

	uint32_t ip;
	int port;

	ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	port = ((struct sockaddr_in *)addr)->sin_port;

  // If it's not INADDR_ANY
  // if ip == INADDR_ANY (ip = 0)
  auto iter2 = pid_sockfd_by_ip_port.find(std::pair<uint32_t, int>(ip, port));
	if(iter2 != pid_sockfd_by_ip_port.end())
		this->returnSystemCall(syscallUUID, -1);

	//Check if INADDR_ANY is already using the port
  iter2 = pid_sockfd_by_ip_port.find(std::pair<uint32_t, int>(0, port));
	if (iter2 != pid_sockfd_by_ip_port.end())
    this->returnSystemCall(syscallUUID, -1);


  auto &s = iter->second;

  s.isBound = true;
  s.ip = ip;
  s.port = port;
  s.addr = *addr;
  s.addrlen = addrlen;

  pid_sockfd_by_ip_port[std::pair<uint32_t, int>(ip, port)] = {pid, sockfd};

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

std::pair<in_addr_t, in_port_t> TCPAssignment::untie_addr(sockaddr addr)
{
	return { ntohl(((sockaddr_in *)&addr)->sin_addr.s_addr), ntohs(((sockaddr_in *)&addr)->sin_port) };
}

sockaddr TCPAssignment::tie_addr(in_addr_t ip, in_port_t port)
{
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);
	return *(sockaddr *)(&addr);
}

void TCPAssignment::write_packet_header(Packet *new_packet,
  size_t ip_start, size_t tcp_start,
  in_addr_t local_ip, in_addr_t remote_ip,
  in_port_t local_port, in_port_t remote_port)
{
  uint32_t ip_buffer;
	uint16_t port_buffer;
  ip_buffer = htonl(local_ip);
	new_packet->writeData(ip_start + 12, &ip_buffer, 4);
	ip_buffer = htonl(remote_ip);
	new_packet->writeData(ip_start + 16, &ip_buffer, 4);

	port_buffer = htons(local_port);
	new_packet->writeData(tcp_start + 0, &port_buffer, 2);
	port_buffer = htons(remote_port);
	new_packet->writeData(tcp_start + 2, &port_buffer, 2);

  // Can new_data_ofs_ns and window_size change?
	uint8_t new_data_ofs_ns = 5 << 4;
	uint16_t window_size = htons(51200);
	new_packet->writeData(tcp_start + 12, &new_data_ofs_ns, 1);
	new_packet->writeData(tcp_start + 14, &window_size, 2);

  return;
}

void TCPAssignment::write_packet_response(Packet *new_packet,
  size_t ip_start, size_t tcp_start,
  uint8_t new_flag, uint32_t new_seq_num, uint32_t new_ack_num,
  in_addr_t local_ip, in_addr_t remote_ip)
{
  uint8_t tcp_header_buffer[20];
	uint16_t checksum;

  new_packet->writeData(tcp_start + 13, &new_flag, 1);
  new_packet->writeData(tcp_start + 4, &new_seq_num, 4);
  new_packet->writeData(tcp_start + 8, &new_ack_num, 4);

  new_packet->readData(tcp_start, tcp_header_buffer, 20);
  checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
  checksum = ~checksum;
  checksum = htons(checksum);
  new_packet->writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

  return;
}

} // namespace E
