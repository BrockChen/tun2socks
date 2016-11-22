// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: test_data.h
// Description: 测试数据，来源wireshark产生
//              对于ip header的测试，直接通过copy internet protocol得到
//              一个20字节的header数据
//              对于tcp的测试，可以直接在frames列表中copy得到完整的一帧的
//              数据，包含了以太网的头，所以要去掉前16字节
//              对于一个完整的流程，可以通过tcp的跟踪tcp流来得到，它相当于
//              在wireshark中过滤tcp.stream eq 657，然后会列出整个从三次
//              握手-》数据交流-》四次断开 整个过滤的数据包，注意，四次挥手不
//              一定是四次，当被关闭的一方发送ack和fin给主动关闭的一方时，它
//              这两个包可能是一起发送
//
//              当某个主机开启一个TCP会话时，他的初始序列号是随机的，可能是0和
//              4,294,967,295之间的任意值，然而，像Wireshark这种工具，通常
//              显示的都是相对序列号/确认号，而不是实际序列号/确认号，相对序列
//              号/确认号是和TCP会话的初始序列号相关联的。
//              注意seq和ack在wireshark中是相对的，如果想要关闭相对序
//              列号/确认号，可以选择Wireshark菜单栏中的 Edit ->
//              Preferences ->protocols ->TCP，去掉Relative sequence number
//              后面勾选框中的√即可
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-16 14:42:42


#ifndef TEST_TEST_DATA_H_
#define TEST_TEST_DATA_H_

#include <stdlib.h>


// 这里是一次完整的post请求过程
extern uint8_t conn_syn[100];  // 78  c->s
extern uint8_t conn_syn_ack[100];  // 78  s->c
extern uint8_t conn_ack[100];  // 54 c->s

extern uint8_t data_post[200];  // 135  c->s
extern uint8_t data_post_ack[100];  // 60 s->c

extern uint8_t data_response_segment1[300];  // 286  s->c
extern uint8_t data_response_segment1_ack[100];  // 54  c->s
extern uint8_t data_response_segment2[300];  // 243  s->c
extern uint8_t data_response_segment2_ack[100];  // 54  c->s

extern uint8_t close_fin_ack[100];  // 54 c->s
extern uint8_t close_fin_ack2[100];  // 74 s->c
extern uint8_t close_ack[100];  // 74 c->s


extern void init_data();
extern void set_hexstr_to_int8array(const char* hexstr, uint8_t* out);


#endif  // TEST_TEST_DATA_H_
