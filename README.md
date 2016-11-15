# tun2socks
 Accepts all incoming TCP connections , and forwards the connections through a SOCKS server

## structure

                                                  +---------------+
                                             +--->|  tcp_conn_cb  |---+
                                             |    +---------------+   |
    +----------------+ -----> +-----------+  |    +---------------+   |   +-----------------+ -----> +---------------+
    |ip packet frames|        |tcp segment+--+--->|  tcp_read_cb  |---+->>| virtual program |        |  socks proxy  |
    +----------------+ <----- +-----------+       +---------------+   +---+-----------------+ <----- +---------------+
                                    ^             +---------------+   |
                                    +-------------|   tcp_write   |<--+
                                                  +---------------+

## tips

### ip layer
this layer has to reassemble the datagram and pass it to the higher protocol layer. 

### tcp layer
if ip packet frames come from host apps, and because of it not recv or send data by network, so it don't need set timeout and retransmission
