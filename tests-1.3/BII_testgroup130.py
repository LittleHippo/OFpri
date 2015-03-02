# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 130 verifies that the correct behavior of the action set. Because most action set tests require more than a single table to properly execute, a majority of test suite 130 is excluded from the basic conformance requirements.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass 130.220. If a device only supports the minimal output action type then test case 130.250 cannot be tested, and its result shall be not applicable or pass.


"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep

class Testcase_130_220_Set_Output(base_tests.SimpleDataPlane):
    """
    Purpose
    Default behavior in case no group action specified

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), Write-Action instruction with output action to a data port. Send a matching packet on the data plane. Verify the packet is forwarded only to this specific port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 130.220 action set output")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.write_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to port %d", out_port)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, [out_port])

    