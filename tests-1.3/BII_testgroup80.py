# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 80 verifies the behavior of OXM types and their corresponding prerequisites.
Remarks
Test case results will be based upon the prerequisite behavior presented by the device vendor. Devices that do not have prerequisite checking must successfully install a flow. Devices with prerequisite checking must throw errors for inconsistent OXM match types.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass test cases 80.180 - 80.200.


"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *

class Testcase_80_180_Missing_Prerequisite(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify device behavior with missing required pre-requisite field

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add flows with missing prerequisites according to table 7.2.3.8. Verify the switch does not accept the flows, and returns the correct error message OFPET_BAD_MATCH and code OFPBMC_BAD_PREREQ for each instance.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 80.180 Missing prerequisite on single header field")

        delete_all_flows(self.controller)
        out_port, bad_port = openflow_ports(2)
        table_id = test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on UDP source Port with missing pre-requisites
        match = ofp.match([
                ofp.oxm.udp_src(53),
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Inserting a flow to match on IPv4 UDP source Port (with missing pre-requisites) and action output to port %s", out_port)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Din't receive an error message, installed flow successfully")
        logging.info("Switch generated an error")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_MATCH,"Reply type is not OFPET_BAD_MATCH")
        logging.info("Error type is OFPET_BAD_MATCH")
        self.assertEqual(reply.code,ofp.const.OFPBMC_BAD_PREREQ, "Reply code is not OFPBMC_BAD_PREREQ")
        logging.info("Error Code is OFPBMC_BAD_PREREQ")
 

class Testcase_80_190_Prerequisite_wrong_position(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify device behavior when pre-requisite field is entered too late in a flow entry

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add flows with prerequisites according to table 7.2.3.8, but with the needed pre-requisite field entered after the respective match field. The match fields should make sense (ie 0x800 with ip_src). Verify the switch does not accept the flows, and returns the correct error message OFPET_BAD_MATCH and code OFPBMC_BAD_PREREQ for each instance.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 80.190 Pre-requisite field on wrong position in flow entry")
        delete_all_flows(self.controller)
        out_port, bad_port = openflow_ports(2)
        table_id = test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on IPv4 source address (Pre-requisite field on wrong position) 
        match = ofp.match([
                ofp.oxm.ipv4_src_masked(0xc0a80000, 0xfffff000),
                ofp.oxm.eth_type(0x0800),
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Inserting a flow to match on IPv4 UDP source Port (with wrong pre-requisites) and action output to port %s", out_port)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Din't receive an error message, installed flow successfully")
        logging.info("Switch generated an error")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_MATCH,"Reply type is not OFPET_BAD_MATCH")
        logging.info("Error type is OFPET_BAD_MATCH")
        self.assertEqual(reply.code,ofp.const.OFPBMC_BAD_PREREQ, "Reply code is not OFPBMC_BAD_PREREQ")
        logging.info("Error Code is OFPBMC_BAD_PREREQ")


class Testcase_80_200_Multiple_instances_same_OXM_TYPE(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify behavior when a flow entry repeats an OXM_TYPE

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow with a duplicated OXM_TYPE field. Verify the switch does not accept the flow, and returns the correct error message OFPET_BAD_MATCH and code OFPBMC_DUP_FIELD.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 80.200 Multiple instances of the same OXM_TYPE in a flow entry")
        delete_all_flows(self.controller)
        out_port, bad_port = openflow_ports(2)
        table_id = test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on IPv4 UDP source Port with a wrong pre-requisite(ip_proto=6)
        match = ofp.match([
                ofp.oxm.eth_type(0x0800),
                ofp.oxm.ip_proto(17),
                ofp.oxm.udp_src(53),
                ofp.oxm.ip_proto(17),
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Inserting a flow to match on IPv4 UDP source Port (with duplicated oxm_types) and action output to port %s", out_port)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Din't receive an error message, installed flow successfully")
        logging.info("Switch generated an error")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_MATCH,"Reply type is not OFPET_BAD_MATCH")
        logging.info("Error type is OFPET_BAD_MATCH")
        self.assertEqual(reply.code,ofp.const.OFPBMC_DUP_FIELD, "Reply code is not OFPBMC_DUP_FIELD")
        logging.info("Error Code is OFPBMC_DUP_FIELD")
        