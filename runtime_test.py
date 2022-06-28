import p4runtime_sh.shell as sh

sh.setup(
    device_id=1,
    grpc_addr='localhost:50001',
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig('build/p4info.txt', 'build/bmv2.json')
)

te = sh.TableEntry("ingress.table0_control.table0")(
   action="ingress.table0_control.set_egress_port"
)
te.priority = 1
te.match["standard_metadata.ingress_port"] = "2"
te.action["port"] = "1"
te.insert()

te2 = sh.TableEntry("ingress.table0_control.table0")(
   action="ingress.table0_control.set_egress_port"
)
te2.priority = 1
te2.match["standard_metadata.ingress_port"] = "1"
te2.action["port"] = "2"
te2.insert()

sh.teardown()

sh.setup(
    device_id=1,
    grpc_addr='localhost:50002',
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig('build/p4info.txt', 'build/bmv2.json')
)

te = sh.TableEntry("ingress.table0_control.table0")(
   action="ingress.table0_control.set_egress_port"
)
te.priority = 1
te.match["standard_metadata.ingress_port"] = "2"
te.action["port"] = "1"
te.insert()

te2 = sh.TableEntry("ingress.table0_control.table0")(
   action="ingress.table0_control.set_egress_port"
)
te2.priority = 1
te2.match["standard_metadata.ingress_port"] = "1"
te2.action["port"] = "2"
te2.insert()

sh.teardown()
