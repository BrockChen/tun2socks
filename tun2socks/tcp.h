// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-12 15:37:38
//                  tcp header for big Endian hosts
// 0---------------------------15-----------------------------31----
// |       Source Port         |         Destination Port     |  ^
// +---------------------------+------------------------------+  |
// |                    Sequence Number                       |  |
// +----------------------------------------------------------+  |
// |            Acknowledgment Number (if ACK set)            | 20 bytes
// +-----+-----+C+E+U+A+P+R+S+F+------------------------------+  |
// |thl reservedW|C|R|C|S|S|Y|I|          Window              |  |
// +-----+-----+R+E+G+K+H+T+N+N+------------------------------+  |
// |        Checksum           |        Urgent Pointer        |  v
// +---------------------------+------------------------------+ ----
// |                    Options(if exist)                     |
// +----------------------------------------------------------+
// |                       payload                            |
// +----------------------------------------------------------+
//

#ifndef TUN2SOCKS_TCP_H_
#define TUN2SOCKS_TCP_H_

#include <stdint.h>
#include <map>
#include <thread>  // NOLINT
#include <mutex>  // NOLINT
#include <condition_variable>  // NOLINT
#include <string>
#include "tun2socks/define.h"
#include "tun2socks/ip4.h"

// tcp连接的状态
enum tcp_states {
  // Server端的某个Socket正在监听来自远方的TCP端口的连接请求。
  TCP_LISTEN,

  // 发送连接请求后等待确认信息。当客户端Socket进行Connect连接时，会首先发
  // 送SYN包，随即进入SYN_SENT状态，然后等待Server端发送三次握手中的第2个包。
  TCP_SYN_SENT,

  // Server端收到一个连接请求FIN后回送确认信息和对等的连接请求(ACK+FIN)，
  // 然后等待确认信息。
  TCP_SYN_RECEIVED,

  // 表示连接已经建立，可以进行数据传输。
  TCP_ESTABLISHED,

  // 主动关闭连接的一方等待对方返回ACK包。
  // 若Socket在ESTABLISHED状态下主动关闭连接并向对方发送FIN包（表示己方不再有数
  // 据需要发送），则进入FIN_WAIT_1状态，等待对方返回ACK包，此后还能读取数据，但
  // 不能发送数据。在正常情况下，无论对方处于何种状态，都应该马上返回ACK包，所以
  // FIN_WAIT_1状态一般很难见到
  TCP_FIN_WAIT_1,

  // 主动关闭连接的一方收到对方返回的ACK包后，等待对方发送FIN包。处于
  // FIN_WAIT_1状态下的Socket收到了对方返回的ACK包后，便进入FIN_WAIT_2状态。
  // 由于FIN_WAIT_2状态下的Socket需要等待对方发送的FIN包，所有常常可以看到。
  // 若在FIN_WAIT_1状态下收到对方发送的同时带有FIN和ACK的包时，则直接进入TIME_WAIT
  // 状态，无须经过FIN_WAIT_2状态。通过wireshark抓包通过看到的断开只会有次挥手的
  // 原因就是FIN和ACK包一起返回，因为大部分情况下都是被关闭的一方已经把数据发送完了，
  // 不会有数据发送给另一方了，所以它会一起返回FIN。
  TCP_FIN_WAIT_2,

  // 初始状态，表示没有任何连接。
  TCP_CLOSE,

  // 表示被动关闭连接的一方在等待关闭连接。当收到对方发送的FIN包后（表示对方
  // 不再有数据需要发送），相应的返回ACK包，然后进入CLOSE_WAIT状态。在该状态下，
  // 若己方还有数据未发送，则可以继续向对方进行发送，但不能再读取数据，直到数据发送完毕。
  TCP_CLOSE_WAIT,


  // 比较罕见的例外状态。正常情况下，发送FIN包后应该先收到（或同时收到）对方
  // 的ACK包，再收到对方的FIN包，而CLOSING状态表示发送FIN包后并没有收到对方
  // 的ACK包，却已收到了对方的FIN包。有两种情况可能导致这种状态：其一，如果
  // 双方几乎在同时关闭连接，那么就可能出现双方同时发送FIN包的情况；其二，如
  // 果ACK包丢失而对方的FIN包很快发出，也会出现FIN先于ACK到达。
  TCP_CLOSING,

  // 被动关闭连接的一方在CLOSE_WAIT状态下完成数据的发送后便可向对方发送FIN包
  // （表示己方不再有数据需要发送），然后等待对方返回ACK包。收到ACK包后便回到CLOSED
  // 状态，释放网络资源。
  TCP_LAST_ACK,

  // 主动关闭连接的一方收到对方发送的FIN包后返回ACK包（表示对方也不再有
  // 数据需要发送，此后不能再读取或发送数据），然后等待足够长的时间（2MSL）以
  // 确保对方接收到ACK包（考虑到丢失ACK包的可能和迷路重复数据包的影响），最后
  // 回到CLOSED状态，释放网络资源。注意linux服务器上经常会看到TIME_WAIT过多
  // 很大原因就是等待的时间太长(MSL时间：MSL在RFC 1122上建议是2分钟,
  // berkeley的TCP实现传统上使用30秒。)。
  TCP_TIME_WAIT,
};

// TCP头部，总长度20字节
struct tcp_hdr {
  uint16_t sport;          // 源端口号
  uint16_t dport;          // 目的端口号
  uint32_t seq;            // 序列号
  uint32_t ack_seq;        // 确认号
  uint8_t reserved : 4;    // 保留位
  uint8_t thl : 4;         // tcp头部长度

  // uint8_t flags;           // 8位标志
  uint8_t fin : 1,
    syn : 1,
    rst : 1,
    psh : 1,
    ack : 1,
    urg : 1,
    ece : 1,
    cwr : 1;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  uint16_t win;            // 16位窗口大小
  uint16_t csum;           // 16位TCP检验和
  uint16_t urp;            // 16为紧急指针
} __attribute__((packed));

typedef struct tcp_segment {
  uint16_t sport;      // 源端口号
  uint16_t dport;      // 目的端口号
  uint32_t seq;        // first sequence number of a segment
  uint32_t ack;        // acknowledgment from the receiving TCP (next
                       // sequence number expected by the receiving TCP)
  uint8_t thl;         // tcp头部长度
  uint8_t flags;       // 8位标志
  uint32_t dlen;
  uint32_t len;        // the number of octets occupied by the data in the
                       // segment (counting SYN and FIN)
  uint32_t win;
  uint16_t csum;       // 16位TCP检验和
  uint32_t up;         // 段紧急指针
  uint32_t prc;        // precedence value, not used
  uint32_t seq_last;   // last sequence number of a segment
  uint8_t *data;
} tcp_segment;

// Protocol control block for the TCP connection
struct tcp_pcb {
  enum tcp_states state;
  uint32_t srcaddr;           // 源IP地址
  uint32_t dstaddr;           // 目的IP地址
  uint16_t sport;      // 源端口号
  uint16_t dport;      // 目的端口号

  uint32_t seq;
  // 发送相关字段
  uint32_t snd_una;  // 最老还没有被确认的序列号 unacknowledged
  uint32_t snd_nxt;  // 下一个将要发送的序列号
  uint32_t snd_wnd;  // 发送窗口
  uint32_t snd_up;   // 发送优先指针
  uint32_t snd_wl1;  // 上次窗口更新时的序列号
  uint32_t snd_wl2;  // 上次窗口更新时的确认号
  uint32_t iss;      // 初始发送序列号

  // 接收相关字段
  uint32_t rcv_nxt;  // 期望接收的下一个字节，即它向发送端 ACK 的序号
  uint32_t rcv_wnd;  // 接收窗口
  uint32_t rcv_up;   // 接收优先指针
  uint32_t irs;      // 初始接收序列号

  uint8_t recved_fin;  // 是否收到了fin，用于发送ack之后，判断状态

  uint8_t flags;                     // 附加状态信息
#define TF_ACK_DELAY (uint8_t)0x01U  // Delayed ACK
#define TF_ACK_NOW   (uint8_t)0x02U  // Immediate ACK
#define TF_INFR      (uint8_t)0x04U  // In fast recovery
#define TF_RESET     (uint8_t)0x08U  //  Connection was reset.
#define TF_CLOSED    (uint8_t)0x10U  //  Connection was sucessfully closed
#define TF_GOT_FIN   (uint8_t)0x20U  // Connection was closed by the remote end
#define TF_NODELAY   (uint8_t)0x40U  // Disable Nagle algorithm
};

extern std::map<std::string, struct tcp_pcb*> pcbs;

int tcp_in(const ip_packet *ip);
tcp_segment* parse_segment(const ip_packet *ip);
void drop_tcp(struct tcp_segment *seg);
struct tcp_pcb* lookup_pcb(uint32_t srcip, uint16_t srcport,
                           uint32_t dstip, uint16_t dstPort);

int generate_iss();

#endif  // TUN2SOCKS_TCP_H_

