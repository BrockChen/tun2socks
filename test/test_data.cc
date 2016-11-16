// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: test_data.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-16 15:05:18

#include "test_data.h"
#include <stdlib.h>
#include <string.h>



uint8_t conn_syn[100];  // 78  c->s
uint8_t conn_syn_ack[100];  // 78  s->c
uint8_t conn_ack[100];  // 54 c->s

uint8_t data_post[200];  // 135  c->s
uint8_t data_post_ack[100];  // 60 s->c

uint8_t data_response_segment1[300];  // 286  s->c
uint8_t data_response_segment1_ack[100];  // 54  c->s
uint8_t data_response_segment2[300];  // 243  s->c
uint8_t data_response_segment2_ack[100];  // 54  c->s

uint8_t close_fin_ack[100];  // 54 c->s
uint8_t close_fin_ack2[100];  // 74 s->c
uint8_t close_ack[100];  // 74 c->s



void init_data() {
  char conn_syn_hex[] = {"0022aae55bd5000ec6c71b29080045000040b64f4000400"
                         "60000c0a801bb6e4c130be557005064302f4a00000000b0"
                         "c2ffff43ed0000020405b4010303050101080a3da8fc160"
                         "000000004020000"};
  char conn_syn_ack_hex[] = {"000ec6c71b290022aae55bd5080045000040b64f400"
                             "036064aae6e4c130bc0a801bb0050e5573431b86164"
                             "302f4bb01232a05ffb0000020405a00101010101010"
                             "101010101010101010104020000"};
  char conn_ack_hex[] = {"0022aae55bd5000ec6c71b29080045000028d2d64000400"
                         "60000c0a801bb6e4c130be557005064302f4b3431b86250"
                         "10ffff43d50000"};
  char data_post_hex[] = {"0022aae55bd5000ec6c71b290800450000799dd440"
                          "0040060000c0a801bb6e4c130be557005064302f4b"
                          "3431b8625018ffff44260000474554202f636f6e66"
                          "69672f706361735f6d61632e6a736f6e2048545450"
                          "2f312e310d0a486f73743a20736563636c69656e74"
                          "67772e616c697061792e636f6d0d0a416363657074"
                          "3a202a2f2a0d0a0d0a"};
  char data_post_ack_hex[] = {"000ec6c71b290022aae55bd5080045000028cc"
                              "cb40003306374a6e4c130bc0a801bb0050e557"
                              "3431b86264302f9c50103908cd090000000020"
                              "202020"};
  char data_response_segment1_hex[] = {"000ec6c71b290022aae55bd508004"
                                       "5000110cccc4000330636616e4c13"
                                       "0bc0a801bb0050e5573431b862643"
                                       "02f9c5018390845f1000048545450"
                                       "2f312e3120323030204f4b0d0a536"
                                       "5727665723a2054656e67696e652f"
                                       "312e342e360d0a446174653a20576"
                                       "5642c203136204e6f762032303136"
                                       "2031303a33343a323120474d540d0"
                                       "a436f6e74656e742d547970653a20"
                                       "6170706c69636174696f6e2f6f637"
                                       "465742d73747265616d0d0a436f6e"
                                       "74656e742d4c656e6774683a20313"
                                       "8390d0a4c6173742d4d6f64696669"
                                       "65643a205765642c203136204e6f7"
                                       "620323031362031303a33303a3036"
                                       "20474d540d0a436f6e6e656374696"
                                       "f6e3a206b6565702d616c6976650d"
                                       "0a4163636570742d52616e6765733"
                                       "a2062797465730d0a0d0a"};
  char data_response_segment1_ack_hex[] = {"0022aae55bd5000ec6c71b290"
                                           "8004500002892414000400600"
                                           "00c0a801bb6e4c130be557005"
                                           "064302f9c3431b94a5010ffff43d50000"};
  char data_response_segment2_hex[] = {"000ec6c71b290022aae55bd508004"
                                       "50000e5cccd40003306368b6e4c13"
                                       "0bc0a801bb0050e5573431b94a643"
                                       "02f9c50183908655900007b226578"
                                       "74656e73696f6e5f666978223a5b7"
                                       "b2276657273696f6e223a312c2273"
                                       "7769746368223a66616c73652c226"
                                       "368726f6d655f6669785f76657222"
                                       "3a5b33322c33332c33342c33352c3"
                                       "3362c33375d2c22626c61636b223a"
                                       "5b2233362e302e313933332e30222"
                                       "c2233362e302e313934312e30222c"
                                       "2233362e302e313936342e34222c2"
                                       "233362e302e313938352e3138222c"
                                       "2233362e302e313938352e3132322"
                                       "25d7d5d2c22726566726573685469"
                                       "6d65223a3134343030307d"};

  char data_response_segment2_ack_hex[] = {"0022aae55bd5000ec6c71b2908"
                                           "00450000286843400040060000"
                                           "c0a801bb6e4c130be557005064"
                                           "302f9c3431ba075010ffff43d50000"};

  char close_fin_ack_hex[] = {"0022aae55bd5000ec6c71b29080045000028fc"
                              "4f400040060000c0a801bb6e4c130be5570050"
                              "64302f9c3431ba075011ffff43d50000"};
  char close_fin_ack2_hex[] = {"000ec6c71b290022aae55bd5080045000028"
                               "ccce4000330637476e4c130bc0a801bb0050"
                               "e5573431ba0764302f9d50113908cb620000"
                               "000020202020"};
  char close_ack_hex[] = {"0022aae55bd5000ec6c71b290800450000287f394"
                          "00040060000c0a801bb6e4c130be557005064302f"
                          "9d3431ba085010ffff43d50000"};

  set_hexstr_to_int8array(conn_syn_hex, conn_syn);
  set_hexstr_to_int8array(conn_syn_ack_hex, conn_syn_ack);
  set_hexstr_to_int8array(conn_ack_hex, conn_ack);

  set_hexstr_to_int8array(data_post_hex, data_post);
  set_hexstr_to_int8array(data_post_ack_hex, data_post_ack);

  set_hexstr_to_int8array(data_response_segment1_hex,
                          data_response_segment1);
  set_hexstr_to_int8array(data_response_segment1_ack_hex,
                          data_response_segment1_ack);
  set_hexstr_to_int8array(data_response_segment2_hex,
                          data_response_segment2);
  set_hexstr_to_int8array(data_response_segment2_ack_hex,
                          data_response_segment2_ack);

  set_hexstr_to_int8array(close_fin_ack_hex, close_fin_ack);
  set_hexstr_to_int8array(close_fin_ack2_hex, close_fin_ack2);
  set_hexstr_to_int8array(close_ack_hex,  close_ack);
}


void set_hexstr_to_int8array(const char* hexstr, uint8_t* out) {
  int index = 0;
  for (size_t i = 28; i < strlen(hexstr);) {  // 14字节ethernet header
    static char data[10] = {'\0'};
    memset(data, 0, sizeof(data));
    strncpy(data, hexstr+i, 2);
    int number = static_cast<int>(strtol(data, NULL, 16));
    out[index] = (uint8_t)number;
    index++;
    i += 2;
  }
}
