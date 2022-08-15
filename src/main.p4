// main.p4
#include <core.p4>
#include <v1model.p4>

#define HASH_BASE 10w0
#define HASH_MAX 10w1023
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
    bit<8>  flags;
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
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<32> hashed_address;
    bit<32> curr_pcaket_length;
    bit<48> curr_interval;
    bit<8> fin_value;
    bit<8> syn_value;
}
struct local_metadata_t { 
    bit<64> my_flowID;
    bit<32> hashed_address;
}

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

    register<bit<32>>(1024) pkt_counter;
    register<bit<48>>(1024) last_time_reg;

	action commpute_flow_id () {
		user_md.my_flowID[31:0]=hdr.ipv4.src_addr;
		user_md.my_flowID[63:32]=hdr.ipv4.dst_addr;
        hash(user_md.hashed_address, HashAlgorithm.crc16, HASH_BASE,
		{hdr.ipv4.src_addr, 7w11, hdr.ipv4.dst_addr}, HASH_MAX);
	}
    
    apply {
    bit<8> fin_value = 0;
	bit<8> syn_value = 0;
	bit<32> pkt_counter_value;
    bit<32> curr_pcaket_length;
    bit<48> last_time;
    bit<48> curr_interval = 0;
    bit<32> src_ip = 0;
    bit<32> dst_ip = 0;
    bit<32> flow_ip = 0;

    if(hdr.ipv4.isValid()){
        src_ip = hdr.ipv4.src_addr;
        dst_ip = hdr.ipv4.dst_addr;
        flow_ip = src_ip + dst_ip;
        commpute_flow_id();
    }

	pkt_counter.read(pkt_counter_value, user_md.hashed_address);
    last_time_reg.read(last_time, user_md.hashed_address);

	pkt_counter_value = pkt_counter_value + 1;
	pkt_counter.write(user_md.hashed_address, pkt_counter_value);
    curr_pcaket_length = st_md.packet_length;

    //initialize interval of current packet and last packet
    if(pkt_counter_value >= 2){
        curr_interval = st_md.ingress_global_timestamp - last_time;
    }
	last_time_reg.write(user_md.hashed_address, st_md.ingress_global_timestamp);

	if(hdr.tcp.isValid()){
            if (hdr.tcp.flags == 1) {
                fin_value = 1;
            }
            if (hdr.tcp.flags == 2) {
                syn_value = 1;
            }
        }
    digest<mac_learn_digest_t>(1, {user_md.hashed_address, src_ip, dst_ip, curr_pcaket_length, curr_interval, fin_value, syn_value});
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
