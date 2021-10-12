Programming Assignment #2

We used following data structures to implement basic socket related system calls and 3-way handshake.

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

DataInfo is where the context of packet is saved. When packed is arrived, it is
read and saved here. Also, when sending a packet, DataInfo is used for passing the arguments.

typedef struct _Socket
{
  int pid;
  int fd;

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

  std::queue<Packet> *listen_queue;
  std::queue<DataInfo> *accept_queue;
  unsigned int backlog;
} Socket;

Socket is created when syscall_socket is called. It is managed by process, and
by using map structure that is given later, we assure there is no packet with same
(pid, fd) value.

Listen_queue is used to implement backlog functionality, which makes a packet be able to be queued.
Accept_queue is used to implement blocking nature of connect(). When accept_queue
is empty, connect() is blocked until an element is appended.

typedef struct _Process
{
  sockaddr *addr;
  socklen_t *addrlen;
  UUID syscallUUID;
} Process;

Some system calls need to be blocked for a while: like accept() and connect().
Process structure is used to save information of processes that has to be blocked
by calling upper system calls.

// (pid, sockfd) -> Socket
std::map<std::pair<int, int>, Socket> sockets;

// (ip, port) -> (pid, sockfd)
std::map<std::pair<in_addr_t, in_port_t>, std::pair<int, int>> pid_sockfd_by_ip_port;

// (pid, sockfd) -> DataInfo
std::map<std::pair<int, int>, DataInfo> data_infos;

// (pid) -> (Process) (Note: ONLY BLOCKED PROCESS IS HERE)
std::map<int, Process> blocked_process_table;
