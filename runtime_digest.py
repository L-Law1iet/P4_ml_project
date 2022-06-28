#!/usr/bin/env python3
"""
mininet >
h1 route add default gw 10.0.0.254 dev h1-eth0
h1 arp -i h1-eth0 -s 10.0.0.254 00:00:0a:00:00:fe
"""
import logging
import os
import queue
import sys
import threading
import traceback
import re

import google.protobuf.text_format
from google.rpc import status_pb2, code_pb2
import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

# parameters
device_id = 1
P4INFO = os.getenv('P4INFO', 'build/p4info.txt')
P4BIN = os.getenv('P4BIN', 'build/bmv2.json')
passed_digest_id = 402184575
failed_digest_id = 401776493
digest_id = passed_digest_id

logging.basicConfig(
        format='%(asctime)s.%(msecs)03d: %(process)d: %(levelname).1s/%(name)s: %(filename)s:%(lineno)d: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO)
send_queue = queue.Queue()
recv_queue = queue.Queue()

def gen_handshake(election_id):
    req = p4runtime_pb2.StreamMessageRequest()
    arbitration = req.arbitration
    arbitration.device_id = device_id
    eid = arbitration.election_id
    eid.high = election_id[0]
    eid.low = election_id[1]
    return req

def check_handshake():
    rep = recv_queue.get(timeout=2)
    if rep is None:
        logging.critical("Failed to establish session with server")
        sys.exit(1)
    is_primary = (rep.arbitration.status.code == code_pb2.OK)
    logging.debug("Session established, client is '%s'", 'primary' if is_primary else 'backup')
    if not is_primary:
        logging.info("You are not the primary client, you only have read access to the server")
    else:
        logging.info('You are primary')

def show_state(response):
    response_str = str(response)
    tokens = response_str.split(" ")
    get_data = 0;
    data = []
    
    for token in tokens:
        if get_data == 1:
            #data.append(token)
            value_str = token[1:len(token)-2]
            value_str = value_str.encode('utf-8').decode('unicode_escape')
            value_int = int.from_bytes(bytes(value_str,'latin_1'), byteorder="big")
            data.append(value_int)
            get_data = 0
        if token == "bitstring:":
            get_data = 1

    i = 0
    for state in data:
        if i == 0:
            print("The number of SYN: ", state)
        elif i == 1:
            print("The number of packets: ", state)
        elif i == 2:
            print("The total length of packets: ", state)

        i = i + 1

def stream(stub):
    def recv_handler(responses):
        for response in responses:
            logging.info('Receive response')
            #logging.info(response)
            show_state(response)
            recv_queue.put(response)
    responses = stub.StreamChannel(iter(send_queue.get, None))
    logging.info('created channel')
    recv_thread = threading.Thread(target=recv_handler, args=(responses,))
    recv_thread.start()
    send_queue.put(gen_handshake(election_id=(0, 1)))
    check_handshake()
    logging.info('handshaked')
    return recv_thread

def insert_digest(stub, digest_id):
    req = p4runtime_pb2.WriteRequest()
    req.device_id = device_id
    req.election_id.high = 0
    req.election_id.low = 1
    req.role_id = 0
    update = req.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    digest_entry = update.entity.digest_entry
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 0
    response = stub.Write(req)

def set_fwd_pipe_config(stub, p4info_path, bin_path):
    req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    req.device_id = device_id
    election_id = req.election_id
    election_id.high = 0
    election_id.low = 1
    req.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    with open(p4info_path, 'r') as f1:
        with open(bin_path, 'rb') as f2:
            try:
                google.protobuf.text_format.Merge(f1.read(), req.config.p4info)
            except google.protobuf.text_format.ParseError:
                logging.error("Error when parsing P4Info")
                raise
            req.config.p4_device_config = f2.read()
    return stub.SetForwardingPipelineConfig(req)

def client_main(stub):
    logging.info('SetForwardingPipelineConfig...')
    set_fwd_pipe_config(stub, P4INFO, P4BIN)
    logging.info('SetForwardingPipelineConfig passed')
    logging.info('insert_digest...')
    insert_digest(stub, digest_id)
    logging.info('insert_digest passed')

with grpc.insecure_channel('localhost:50001') as channel:
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
    recv_t = stream(stub)
    try:
        client_main(stub)
        while True:
            cmd = input('> ')
            if cmd.lower() == 'exit': break
            if cmd.lower() == 'quit': break
    except (KeyboardInterrupt, EOFError):
        pass
    except:
        traceback.print_exc()
    send_queue.put(None)
    recv_t.join()
