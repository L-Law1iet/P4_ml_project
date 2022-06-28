// main.p4
#include <core.p4>
#include <v1model.p4>

#define ETH_TYPE_IPV4 0x0800
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}


struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct mac_learn_digest_t {
    //bit<48> src_addr;
    //bit<9>  ingress_port;
    bit<32> num_syn;
    //bit<32> num_fin;
    bit<32> pkt_counter;
    bit<32> pkt_length;
}
struct local_metadata_t { }

parser parser_impl(
        packet_in packet,
        out headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {
    state start { transition parse_ethernet; }

    state parse_ethernet {
	packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }    
}

control deparser(
        packet_out pkt,
        in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
	pkt.emit(hdr.ipv4);
	pkt.emit(hdr.tcp);
    }
}

control ingress(
        inout headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {

    register<bit<32>>(1) syn_counter;
    register<bit<32>>(1) fin_counter;
    register<bit<32>>(1) pkt_counter;
    register<bit<32>>(1) pkt_length;

    apply {
        // passed
        //digest<mac_learn_digest_t>(1, {hdr.ethernet.src_addr, st_md.ingress_port});
	bit<32> syn_value;
        bit<32> fin_value;
	bit<32> pkt_counter_value;
	bit<32> pkt_length_value;
	bit<32> avg_length;
        syn_counter.read(syn_value, 0);
        fin_counter.read(fin_value, 0);
	pkt_counter.read(pkt_counter_value, 0);
	pkt_length.read(pkt_length_value, 0);

	pkt_counter_value = pkt_counter_value + 1;
	pkt_length_value = pkt_length_value + st_md.packet_length;

	pkt_counter.write(0, pkt_counter_value);
	pkt_length.write(0, pkt_length_value);

	

	if(hdr.tcp.isValid()){
            //bit<32> syn_value;
            //bit<32> fin_value;
            //syn_counter.read(syn_value, 0);
            //fin_counter.read(fin_value, 0);
	    //digest<mac_learn_digest_t>(1, {syn_value, fin_value});

            if ((hdr.tcp.ctrl & 0b000010) >> 1 == 1) {
                syn_value = syn_value + 1;
                syn_counter.write(0, syn_value);
                //digest<statistic_t>(1, {syn_value, fin_value});


		digest<mac_learn_digest_t>(1, {syn_value, pkt_counter_value, pkt_length_value});
            }
            if ((hdr.tcp.ctrl & 0b000001) == 1) {
                fin_value = fin_value + 1;
                fin_counter.write(0, fin_value);
                //digest<statistic_t>(1, {syn_value, fin_value});
		//digest<mac_learn_digest_t>(1, {syn_value, fin_value});
            }
        }


	if(st_md.ingress_port == 1){
	    st_md.egress_spec = 2;
	}
	if(st_md.ingress_port == 2){
	    st_md.egress_spec = 1;
	}
    }
}
control egress(
        inout headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {
    apply { }
}
control no_verify_checksum(
        inout headers_t hdr,
        inout local_metadata_t user_md) {
    apply { }
}
control no_compute_checksum(
        inout headers_t hdr,
        inout local_metadata_t user_md) {
    apply { }
}
V1Switch(parser_impl(),
         no_verify_checksum(),
         ingress(),
         egress(),
         no_compute_checksum(),
         deparser()
) main;
