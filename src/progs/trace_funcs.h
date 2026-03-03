#define INDEX_napi_gro_receive_entry 1
#define INDEX_dev_gro_receive 2
#define INDEX_enqueue_to_backlog 3
#define INDEX_netif_receive_generic_xdp 4
#define INDEX_xdp_do_generic_redirect 5
#define INDEX_netif_receive_skb 6
#define INDEX___dev_queue_xmit 7
#define INDEX_dev_hard_start_xmit 8
#define INDEX_tcf_classify 9
#define INDEX_cls_bpf_classify 10
#define INDEX_tcf_bpf_act 11
#define INDEX_qdisc_dequeue 12
#define INDEX_qdisc_enqueue 13
#define INDEX_ipvlan_queue_xmit 14
#define INDEX_ipvlan_handle_frame 15
#define INDEX_ipvlan_rcv_frame 16
#define INDEX_ipvlan_xmit_mode_l3 17
#define INDEX_ipvlan_process_v4_outbound 18
#define INDEX_br_nf_pre_routing 19
#define INDEX_br_nf_forward_ip 20
#define INDEX_br_nf_forward_arp 21
#define INDEX_br_nf_post_routing 22
#define INDEX_arp_rcv 23
#define INDEX_arp_process 24
#define INDEX_bond_dev_queue_xmit 25
#define INDEX___iptunnel_pull_header 26
#define INDEX_vxlan_rcv 27
#define INDEX_vxlan_xmit_one 28
#define INDEX_vlan_do_receive 29
#define INDEX_vlan_dev_hard_start_xmit 30
#define INDEX_netdev_port_receive 31
#define INDEX_ovs_vport_receive 32
#define INDEX_ovs_dp_process_packet 33
#define INDEX_packet_rcv 34
#define INDEX_tpacket_rcv 35
#define INDEX_packet_direct_xmit 36
#define INDEX_ipt_do_table 37
#define INDEX_nft_do_chain 38
#define INDEX_nf_nat_manip_pkt 39
#define INDEX_nf_hook_slow 40
#define INDEX_ipv4_confirm 41
#define INDEX_nf_confirm 42
#define INDEX_ipv4_conntrack_in 43
#define INDEX_nf_conntrack_in 44
#define INDEX_ipv4_pkt_to_tuple 45
#define INDEX_tcp_new 46
#define INDEX_tcp_pkt_to_tuple 47
#define INDEX_resolve_normal_ct 48
#define INDEX_tcp_packet 49
#define INDEX_tcp_in_window 50
#define INDEX___nf_ct_refresh_acct 51
#define INDEX_ip_rcv 52
#define INDEX_ip_rcv_core 53
#define INDEX_ip_rcv_finish 54
#define INDEX_ip_local_deliver 55
#define INDEX_ip_local_deliver_finish 56
#define INDEX_ip_forward 57
#define INDEX_ip_forward_finish 58
#define INDEX_ip6_forward 59
#define INDEX_ip6_rcv_finish 60
#define INDEX_ip6_rcv_core 61
#define INDEX_ipv6_rcv 62
#define INDEX___ip_queue_xmit 63
#define INDEX___ip_local_out 64
#define INDEX_ip_output 65
#define INDEX_ip_finish_output 66
#define INDEX_ip_finish_output_gso 67
#define INDEX_ip_finish_output2 68
#define INDEX_ip6_output 69
#define INDEX_ip6_finish_output 70
#define INDEX_ip6_finish_output2 71
#define INDEX_ip6_send_skb 72
#define INDEX_ip6_local_out 73
#define INDEX_xfrm4_output 74
#define INDEX_xfrm_output 75
#define INDEX_xfrm_output2 76
#define INDEX_xfrm_output_gso 77
#define INDEX_xfrm_output_resume 78
#define INDEX_xfrm4_transport_output 79
#define INDEX_xfrm4_prepare_output 80
#define INDEX_xfrm4_policy_check 81
#define INDEX_xfrm4_rcv 82
#define INDEX_xfrm_input 83
#define INDEX_xfrm4_transport_input 84
#define INDEX_ah_output 85
#define INDEX_esp_output 86
#define INDEX_esp_output_tail 87
#define INDEX_ah_input 88
#define INDEX_esp_input 89
#define INDEX_fib_validate_source 90
#define INDEX_ip_route_input_slow 91
#define INDEX_tcp_v4_rcv 92
#define INDEX_tcp_v6_rcv 93
#define INDEX_tcp_filter 94
#define INDEX_tcp_child_process 95
#define INDEX_tcp_v4_send_reset 96
#define INDEX_tcp_v6_send_reset 97
#define INDEX_tcp_v4_do_rcv 98
#define INDEX_tcp_v6_do_rcv 99
#define INDEX_tcp_rcv_established 100
#define INDEX_tcp_rcv_state_process 101
#define INDEX_tcp_queue_rcv 102
#define INDEX_tcp_data_queue_ofo 103
#define INDEX_tcp_ack_probe 104
#define INDEX_tcp_ack 105
#define INDEX_tcp_probe_timer 106
#define INDEX_tcp_send_probe0 107
#define INDEX___inet_lookup_listener 108
#define INDEX_inet6_lookup_listener 109
#define INDEX_tcp_bad_csum 110
#define INDEX_tcp_sendmsg_locked 111
#define INDEX_tcp_skb_entail 112
#define INDEX_skb_entail 113
#define INDEX___tcp_push_pending_frames 114
#define INDEX___tcp_transmit_skb 115
#define INDEX___tcp_retransmit_skb 116
#define INDEX_tcp_rate_skb_delivered 117
#define INDEX_udp_rcv 118
#define INDEX_udp_unicast_rcv_skb 119
#define INDEX_udp_queue_rcv_skb 120
#define INDEX_xfrm4_udp_encap_rcv 121
#define INDEX_xfrm4_rcv_encap 122
#define INDEX___udp_queue_rcv_skb 123
#define INDEX___udp_enqueue_schedule_skb 124
#define INDEX_icmp_rcv 125
#define INDEX_icmp_echo 126
#define INDEX_icmp_reply 127
#define INDEX_icmpv6_rcv 128
#define INDEX_icmpv6_echo_reply 129
#define INDEX_ping_rcv 130
#define INDEX___ping_queue_rcv_skb 131
#define INDEX_ping_queue_rcv_skb 132
#define INDEX_ping_lookup 133
#define INDEX_inet_listen 134
#define INDEX_tcp_v4_destroy_sock 135
#define INDEX_tcp_close 136
#define INDEX_tcp_send_active_reset 137
#define INDEX_tcp_ack_update_rtt 138
#define INDEX_tcp_write_timer_handler 139
#define INDEX_tcp_retransmit_timer 140
#define INDEX_tcp_enter_recovery 141
#define INDEX_tcp_enter_loss 142
#define INDEX_tcp_try_keep_open 143
#define INDEX_tcp_enter_cwr 144
#define INDEX_tcp_fastretrans_alert 145
#define INDEX_tcp_rearm_rto 146
#define INDEX_tcp_event_new_data_sent 147
#define INDEX_tcp_schedule_loss_probe 148
#define INDEX_tcp_rtx_synack 149
#define INDEX_tcp_retransmit_skb 150
#define INDEX_tcp_rcv_spurious_retrans 151
#define INDEX_tcp_dsack_set 152
#define INDEX_skb_clone 153
#define INDEX_consume_skb 154
#define INDEX_kfree_skb 155
#define INDEX___kfree_skb 156
#define INDEX_kfree_skb_partial 157
#define INDEX_skb_attempt_defer_free 158

#define TRACE_MAX 159
#define DEFINE_ALL_TRACES(FN, FN_tp, FNC)		\
	FN_tp(napi_gro_receive_entry)	\
	FN(dev_gro_receive)	\
	FN(enqueue_to_backlog)	\
	FN(netif_receive_generic_xdp)	\
	FN(xdp_do_generic_redirect)	\
	FN_tp(netif_receive_skb)	\
	FN(__dev_queue_xmit)	\
	FN(dev_hard_start_xmit)	\
	FN(tcf_classify)	\
	FN(cls_bpf_classify)	\
	FN(tcf_bpf_act)	\
	FNC(qdisc_dequeue)	\
	FNC(qdisc_enqueue)	\
	FN(ipvlan_queue_xmit)	\
	FN(ipvlan_handle_frame)	\
	FN(ipvlan_rcv_frame)	\
	FN(ipvlan_xmit_mode_l3)	\
	FN(ipvlan_process_v4_outbound)	\
	FN(br_nf_pre_routing)	\
	FN(br_nf_forward_ip)	\
	FN(br_nf_forward_arp)	\
	FN(br_nf_post_routing)	\
	FN(arp_rcv)	\
	FN(arp_process)	\
	FN(bond_dev_queue_xmit)	\
	FN(__iptunnel_pull_header)	\
	FN(vxlan_rcv)	\
	FN(vxlan_xmit_one)	\
	FNC(vlan_do_receive)	\
	FN(vlan_dev_hard_start_xmit)	\
	FN(netdev_port_receive)	\
	FN(ovs_vport_receive)	\
	FN(ovs_dp_process_packet)	\
	FN(packet_rcv)	\
	FN(tpacket_rcv)	\
	FN(packet_direct_xmit)	\
	FNC(ipt_do_table)	\
	FNC(nft_do_chain)	\
	FN(nf_nat_manip_pkt)	\
	FNC(nf_hook_slow)	\
	FN(ipv4_confirm)	\
	FN(nf_confirm)	\
	FN(ipv4_conntrack_in)	\
	FN(nf_conntrack_in)	\
	FN(ipv4_pkt_to_tuple)	\
	FN(tcp_new)	\
	FN(tcp_pkt_to_tuple)	\
	FN(resolve_normal_ct)	\
	FN(tcp_packet)	\
	FN(tcp_in_window)	\
	FN(__nf_ct_refresh_acct)	\
	FN(ip_rcv)	\
	FN(ip_rcv_core)	\
	FN(ip_rcv_finish)	\
	FN(ip_local_deliver)	\
	FN(ip_local_deliver_finish)	\
	FN(ip_forward)	\
	FN(ip_forward_finish)	\
	FN(ip6_forward)	\
	FN(ip6_rcv_finish)	\
	FN(ip6_rcv_core)	\
	FN(ipv6_rcv)	\
	FN(__ip_queue_xmit)	\
	FN(__ip_local_out)	\
	FN(ip_output)	\
	FN(ip_finish_output)	\
	FN(ip_finish_output_gso)	\
	FN(ip_finish_output2)	\
	FN(ip6_output)	\
	FN(ip6_finish_output)	\
	FN(ip6_finish_output2)	\
	FN(ip6_send_skb)	\
	FN(ip6_local_out)	\
	FN(xfrm4_output)	\
	FN(xfrm_output)	\
	FN(xfrm_output2)	\
	FN(xfrm_output_gso)	\
	FN(xfrm_output_resume)	\
	FN(xfrm4_transport_output)	\
	FN(xfrm4_prepare_output)	\
	FN(xfrm4_policy_check)	\
	FN(xfrm4_rcv)	\
	FN(xfrm_input)	\
	FN(xfrm4_transport_input)	\
	FN(ah_output)	\
	FN(esp_output)	\
	FN(esp_output_tail)	\
	FN(ah_input)	\
	FN(esp_input)	\
	FN(fib_validate_source)	\
	FN(ip_route_input_slow)	\
	FN(tcp_v4_rcv)	\
	FN(tcp_v6_rcv)	\
	FN(tcp_filter)	\
	FN(tcp_child_process)	\
	FNC(tcp_v4_send_reset)	\
	FNC(tcp_v6_send_reset)	\
	FN(tcp_v4_do_rcv)	\
	FN(tcp_v6_do_rcv)	\
	FN(tcp_rcv_established)	\
	FN(tcp_rcv_state_process)	\
	FN(tcp_queue_rcv)	\
	FN(tcp_data_queue_ofo)	\
	FN(tcp_ack_probe)	\
	FN(tcp_ack)	\
	FN(tcp_probe_timer)	\
	FN(tcp_send_probe0)	\
	FN(__inet_lookup_listener)	\
	FN(inet6_lookup_listener)	\
	FN_tp(tcp_bad_csum)	\
	FN(tcp_sendmsg_locked)	\
	FN(tcp_skb_entail)	\
	FN(skb_entail)	\
	FN(__tcp_push_pending_frames)	\
	FN(__tcp_transmit_skb)	\
	FN(__tcp_retransmit_skb)	\
	FN(tcp_rate_skb_delivered)	\
	FN(udp_rcv)	\
	FN(udp_unicast_rcv_skb)	\
	FN(udp_queue_rcv_skb)	\
	FN(xfrm4_udp_encap_rcv)	\
	FN(xfrm4_rcv_encap)	\
	FN(__udp_queue_rcv_skb)	\
	FN(__udp_enqueue_schedule_skb)	\
	FN(icmp_rcv)	\
	FN(icmp_echo)	\
	FN(icmp_reply)	\
	FN(icmpv6_rcv)	\
	FN(icmpv6_echo_reply)	\
	FN(ping_rcv)	\
	FN(__ping_queue_rcv_skb)	\
	FN(ping_queue_rcv_skb)	\
	FN(ping_lookup)	\
	FNC(inet_listen)	\
	FN(tcp_v4_destroy_sock)	\
	FN(tcp_close)	\
	FNC(tcp_send_active_reset)	\
	FNC(tcp_ack_update_rtt)	\
	FN(tcp_write_timer_handler)	\
	FN(tcp_retransmit_timer)	\
	FN(tcp_enter_recovery)	\
	FN(tcp_enter_loss)	\
	FN(tcp_try_keep_open)	\
	FN(tcp_enter_cwr)	\
	FN(tcp_fastretrans_alert)	\
	FN(tcp_rearm_rto)	\
	FN(tcp_event_new_data_sent)	\
	FN(tcp_schedule_loss_probe)	\
	FN(tcp_rtx_synack)	\
	FN(tcp_retransmit_skb)	\
	FN(tcp_rcv_spurious_retrans)	\
	FN(tcp_dsack_set)	\
	FN(skb_clone)	\
	FN_tp(consume_skb)	\
	FNC(kfree_skb)	\
	FN(__kfree_skb)	\
	FN(kfree_skb_partial)	\
	FN(skb_attempt_defer_free)	\


