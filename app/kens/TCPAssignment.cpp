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
    // 		static_cast<struct sockaddr*>(param.param2_ptr),
    // (socklen_t)param.param3_int);
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    break;
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    // 		static_cast<struct sockaddr*>(param.param2_ptr),
    // 		static_cast<socklen_t*>(param.param3_ptr));
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
    // 		static_cast<struct sockaddr *>(param.param2_ptr),
    // 		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {

  return;
  //
  // /* Read Packet START */
  // assert(fromModule == "IPv4");
	// /* Packet arrived from IPv4 Module!
	//  * (1) Read from packet local and remote addresses.
	//  * (2) Forward the packet to corresponding TCPSocket.
	//  * (3) Handle the packet according to the state of the socket.
	//  */
  //
	// const size_t ip_start = 14;  /* Size of Ethernet header */
  //
	// uint8_t ihl_buffer;
	// packet->readData(ip_start, &ihl_buffer, 1);
	// size_t ihl = (ihl_buffer & 0x0f) * 4;  /* Size of the IP header */
  //
	// size_t tcp_start = ip_start + ihl;
	// uint32_t ip_buffer;
	// uint16_t port_buffer;
  //
	// packet->readData(ip_start + 12, &ip_buffer, 4);
	// packet->readData(tcp_start + 0, &port_buffer, 2);
	// in_addr_t remote_ip = (in_addr_t)ntohl(ip_buffer);
	// in_port_t remote_port = (in_port_t)ntohs(port_buffer);
	// // sockaddr remote_addr = tie_addr(remote_ip, remote_port);
  //
	// packet->readData(ip_start + 16, &ip_buffer, 4);
	// packet->readData(tcp_start + 2, &port_buffer, 2);
	// in_addr_t local_ip = (in_addr_t)ntohl(ip_buffer);
	// in_port_t local_port = (in_port_t)ntohs(port_buffer);
	// // sockaddr local_addr = tie_addr(local_ip, local_port);
  // /* Read Packet FINISH */
  //
	// // auto ip_it = ip_set.find(local_port);
	// // if (ip_it == ip_set.end())
	// // {
	// // 	this->freePacket(packet);
	// // 	return;
	// // }
	// // auto &sock_map = ip_it->second;
	// // auto addr_sock_it = sock_map.find(INADDR_ANY);
	// // if(addr_sock_it == sock_map.end())
	// // 	addr_sock_it = sock_map.find(local_ip);
	// // if(addr_sock_it == sock_map.end())
	// // {
	// // 	this->freePacket(packet);
	// // 	return;
	// // }
  //
  // auto iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, int>(local_ip, local_port));
  // if(iter != pid_sockfd_by_ip_port.end())
  // {
  //   	this->freePacket(packet);
  //   	return;
  // }
  //
  // iter = pid_sockfd_by_ip_port.find(std::pair<uint32_t, int>(0, local_port));
  // if (iter != pid_sockfd_by_ip_port.end())
  // {
  //   this->freePacket(packet);
  //   return;
  // }
  //
  // int pid, fd;
  // fd = iter->second;
  //
  // auto iter2 = sockets.find(fd);
  //
  // if(iter2 == sockets.end()){
  //   // Error: Socket not found
  //   // Not sure
  //   this->freePacket(packet);
  //   return;
  // }
  //
  // Socket *s = iter2 ->second;
  // pid = s->pid;
  //
	// // std::tie(pid, fd) = addr_sock_it->second;
	// // auto &pcb = proc_table[pid];
	// // auto &sock = pcb.fd_info[fd];
  //
  // /* Read Packet START AGAIN */
	// uint32_t seq_num;
	// packet->readData(tcp_start + 4, &seq_num, 4);
	// seq_num = ntohl(seq_num);
	// uint32_t ack_num;
	// packet->readData(tcp_start + 8, &ack_num, 4);
	// ack_num = ntohl(ack_num);
  //
	// uint8_t data_ofs_ns;
	// packet->readData(tcp_start + 12, &data_ofs_ns, 1);
	// size_t data_ofs = (data_ofs_ns >> 4) * 4;
  //
	// uint8_t flag;
	// packet->readData(tcp_start + 13, &flag, 1);
  // /* Read Packet FINISH */
  //
  // /* Write Packet START */
	// size_t header_size = tcp_start + data_ofs;
  //
	// Packet *new_packet = allocatePacket(header_size);
  //
	// ip_buffer = htonl(local_ip);
	// new_packet->writeData(ip_start + 12, &ip_buffer, 4);
	// ip_buffer = htonl(remote_ip);
	// new_packet->writeData(ip_start + 16, &ip_buffer, 4);
  //
	// port_buffer = htons(local_port);
	// new_packet->writeData(tcp_start + 0, &port_buffer, 2);
	// port_buffer = htons(remote_port);
	// new_packet->writeData(tcp_start + 2, &port_buffer, 2);
  //
	// uint8_t new_data_ofs_ns = 5 << 4;
	// uint16_t window_size = htons(51200);
	// new_packet->writeData(tcp_start + 12, &new_data_ofs_ns, 1);
	// new_packet->writeData(tcp_start + 14, &window_size, 2);
  //
	// uint8_t tcp_header_buffer[20];
	// uint16_t checksum;
	// uint8_t new_flag;
	// uint32_t new_seq_num;
	// uint32_t new_ack_num;
  // /* Write Packet FINISH */
  //
	// //if (sock.state != ST_BOUND) fprintf(stderr, "Packet state: %d\n", sock.state);
	// switch(s->state)
	// {
	// 	case ST_READY: 		/* Socket is ready. */
	// 		this->freePacket(packet);
	// 		freePacket(new_packet);
	// 		break;
  //
	// 	case ST_BOUND:		/* Socket is bound. */
	// 		this->freePacket(packet);
	// 		freePacket(new_packet);
	// 		break;
  //
	// 	case ST_LISTEN:		/* Connect ready. Only for server. */
	// 		this->freePacket(packet);
	// 		if(flag & SYN)
	// 		{
  //
	// 			new_flag = SYN | ACK;
	// 			new_packet->writeData(tcp_start + 13, &new_flag, 1);
  //
	// 			new_seq_num = htonl(rand_seq_num());
	// 			new_packet->writeData(tcp_start + 4, &new_seq_num, 4);
	// 			new_ack_num = htonl(seq_num + 1);
	// 			new_packet->writeData(tcp_start + 8, &new_ack_num, 4);
  //
	// 			new_packet->readData(tcp_start, tcp_header_buffer, 20);
	// 			checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
	// 			checksum = ~checksum;
	// 			checksum = htons(checksum);
	// 			new_packet->writeData(tcp_start + 16, (uint8_t *)&checksum, 2);
  //
  //       struct Context *c = (struct Context *)malloc(sizeof(struct Context));
  //       c->local_ip = local_ip;
  //       c->local_addr = local_addr;
  //       c->remote_ip = remote_ip;
  //       c->remote_addr = remote_addr;
  //       c->seq_num = ntohl(new_seq_num);
  //       // TODO: ack num is not touched here?
  //
  //       contexts[fd] = c;
  //
	// 			sendPacket("IPv4", new_packet);
  //
	// 			s->state = ST_SYN_RCVD;
	// 		}
	// 		break;
  //
	// 	case ST_SYN_SENT:	/* 3-way handshake, client. */
  // 			this->freePacket(packet);
  // 			if((flag & SYN) && (flag & ACK))
  // 			{
  //         auto context_it = contexts.find(fd);
  //         if (context_it == contexts.end())
  //         {
  //           freePacket(new_packet);
  // 					this->returnSystemCall(pcb.syscallUUID, -1);
  // 					s->state = ST_BOUND;
  // 					break;
  //         }
  // 				if(ack_num != context_it->second->seq_num + 1)
  // 				{
  // 					// connect fail
  // 					freePacket(new_packet);
  // 					this->returnSystemCall(pcb.syscallUUID, -1);
  // 					s->state = ST_BOUND;
  // 					break;
  // 				}
  //
  // 				new_flag = ACK;
  // 				new_packet->writeData(tcp_start + 13, &new_flag, 1);
  //
  // 				new_ack_num = htonl(seq_num + 1);
  // 				new_packet->writeData(tcp_start + 8, &new_ack_num, 4);
  //
  // 				new_packet->readData(tcp_start, tcp_header_buffer, 20);
  // 				checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
  // 				checksum = ~checksum;
  // 				checksum = htons(checksum);
  // 				new_packet->writeData(tcp_start + 16, (uint8_t *)&checksum, 2);
  //
  // 				sendPacket("IPv4", new_packet);
  //
  // 				// assert(pcb.blocked && pcb.syscall == CONNECT);
  //
  // 				s->state = ST_ESTAB;
  //
  // 				this->returnSystemCall(pcb.syscallUUID, 0);
  //         // TODO
  //         // pcb.unblockSyscall();
	// 		}
	// 		else if(flag & SYN)
	// 			;//assert(0);  // Simultaneous open not considered
	// 		break;
  //
	// 	case ST_SYN_RCVD:	/* 3-way handshake, server. */
  //     // TODO
	// 		freePacket(new_packet);
  //     auto context_it = contexts.find(fd);
  //     if (context_it == contexts.end())
  //     {
  //       // TODO: Not sure
  //       return;
  //     }
  //     Context *c = context_it->second;
	// 		if( std::make_pair(c->local_ip, c->local_port) == std::make_pair(local_ip, local_port) &&
	// 			std::make_pair(c->remote_ip, c->remote_port) == std::make_pair(remote_ip, remote_port))
	// 		{
	// 			this->freePacket(packet);
	// 			if(flag & ACK)
	// 			{
  //
	// 				if(ack_num != c->seq_num + 1)
	// 				{
	// 					break;
	// 				}
  //
	// 				if(pcb.blocked)
	// 				{
	// 					assert(pcb.syscall == ACCEPT);
	// 					auto &param = pcb.param.acceptParam;
	// 					int connfd = this->createFileDescriptor(pid);
	// 					//fprintf(stderr, "Waking UUID: %d\n", pcb.syscallUUID);
  //
	// 					if (connfd != -1)
	// 					{
	// 						pcb.fd_info.insert({ connfd, TCPSocket(sock.domain) });
	// 						auto &sock_accept = pcb.fd_info[connfd];
	// 						sock_accept.state = ST_ESTAB;
	// 						sock_accept.context = sock.context;
	// 						*param.addr = sock_accept.context.remote_addr;
	// 						*param.addrlen = sizeof(*param.addr);
	// 					}
  //
	// 					this->returnSystemCall(pcb.syscallUUID, connfd);
	// 					pcb.unblockSyscall();
	// 				}
	// 				else
	// 					sock.queue->accept_queue.push(sock.context);
  //
	// 				sock.state = ST_LISTEN;
  //
	// 				if(!sock.queue->listen_queue.empty())
	// 				{
	// 					new_packet = sock.queue->listen_queue.front();
	// 					sock.queue->listen_queue.pop();
	// 					packetArrived("IPv4", new_packet);
	// 				}
	// 			}
	// 		}
	// 		else
	// 		{
	// 			if(flag & SYN)
	// 			{
	// 				if((int)sock.queue->listen_queue.size() + 1 < sock.queue->backlog)
	// 				{
	// 					new_packet = clonePacket(packet);
	// 					sock.queue->listen_queue.push(new_packet);
	// 				}
	// 			}
	// 			this->freePacket(packet);
	// 		}
	// 		break;
  //
	// 	case ST_ESTAB:		/* Connection established. */
	// 		this->freePacket(packet);
	// 		//assert(0);  // Read/Write not implemented!
	// 		break;
  //
	// 	case ST_FIN_WAIT_1:	/* 4-way handshake, active close. */
	// 	case ST_FIN_WAIT_2:
	// 	case ST_TIME_WAIT:
	// 	case ST_CLOSE_WAIT:	/* 4-way handshake, passive close. */
	// 	case ST_LAST_ACK:
  //
	// 	case ST_CLOSING:	/* Recieved FIN after sending FIN. */
	// 		break;
  //
	// 	default:
	// 		assert(0);
	// }
}

void TCPAssignment::timerCallback(std::any payload) {
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
void syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
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
void syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	// auto sock_it = sockets.find({pid, sockfd});
  //
	// if(sock_it == sockets.end() || sock_it->second.state != ST_BOUND)
	// {
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }
  //
  // Socket s = sock_it->second;
  //
	// s.state = ST_LISTEN;
  //
  // // TODO: Imeplement backlog
  // // s->queue = new PassiveQueue(backlog);
  //
  // this->returnSystemCall(syscallUUID, 0);
}

/*
The accept() call receives 3 parameters from the application layer. It extracts the first
connection on the queue of pending connections. It creates and returns a new file descriptor
for the connection. It also fills the address parameter with connecting client’s information.
More details about the socket call are described https://linux.die.net/man/2/accept and
https://linux.die.net/man/3/accept .
*/
void syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    // auto sock_it = sockets.find({pid, sockfd})
    // if(sock_it == sockets.end()
    //   || (sock_it->second.state != ST_LISTEN
    //     && sock_it->second.state != ST_SYN_RCVD))
    // {
    //   this->returnSystemCall(syscallUUID, -1);
    //   return;
    // }
    //
    // Socket s = sock_it->second;
    //
    // // TODO: Implement queue
    // // auto &accept_queue = s.queue->accept_queue;
    // // if(accept_queue.empty())
    // // {
    // //   //sock.blocked = true;
    // //   //sock.blockedUUID = syscallUUID;
    // //   PCBEntry::syscallParam param;
    // //   param.acceptParam = { sockfd, addr, addrlen };
    // //   pcb.blockSyscall(ACCEPT, syscallUUID, param);
    // //   return;
    // // }
    //
    // int connfd = this->createFileDescriptor(pid);
    // if (connfd != -1)
    // {
    //   fd_info.insert({ connfd, TCPSocket(sock.domain) });
    //   auto &sock_accept = fd_info[connfd];
    //   sock_accept.state = ST_ESTAB;
    //   sock_accept.context = accept_queue.front(); accept_queue.pop();
    //   *addr = sock_accept.context.remote_addr;
    //   *addrlen = sizeof(*addr);
    // }
    //
    // this->returnSystemCall(syscallUUID, connfd);
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

} // namespace E
