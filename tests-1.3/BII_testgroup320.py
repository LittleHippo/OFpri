# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 320 verifies the correct implementation of the fields contained in each of the following 
message structs; ofp_table_stats, ofp_table_features, ofp_table_feature_prop_type, ofp_table_feature_prop_instructions, 
ofp_table_feature_prop_next_tables, ofp_table_feature_prop_actions, and ofp_action_header_action_ids.

To satisfy the basic requirements an OpenFlow enabled device must pass test cases 320.10 - 320.70, 320.130 - 320.480, 
320.500 - 320.520, and 320.540.
"""

import logging
import time
import sys

import unittest
import random
from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message
import BII_testgroup320

from oftest.oflog import *
from oftest.testutils import *
from time import sleep
from loxi.of13.common import table_feature_prop


class Testcase_320_10_MultipartTableStatsCount(base_tests.SimpleDataPlane):
    """
    320.10 - Table Statistics Count
    Verify that the n_tables ofp_table_stats messages are returned in response to a multipart table request.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.10 - Table Statistics Count test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)

        self.assertEqual(len(stats), tables_no, "Table statistics count is not correct")
        logging.info("Table statistics count is correct")



class Testcase_320_20_MultipartTableStatsTableOrder(base_tests.SimpleDataPlane):
    """
    320.20 - /* Identifier of table. Lower numbered tables are consulted first. */
    Verify that the n_tables ofp_table_stats messages are returned in response to a multipart table request 
    from lowest table_id to the highest supported table_id.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.20 - Identifier of table test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table stats reply.")

        self.assertEqual(len(stats), tables_no, "Table statistics count is not correct")
        self.assertTrue(stats[0].table_id < stats[len(stats)-1].table_id, "Table ID is not in order")
        logging.info("Table statistics count is correct")



class Testcase_320_30_MultipartTableStatsActiveEntries(base_tests.SimpleDataPlane):
    """
    320.30 - /* Number of active entries. */
    Verify that the active number is correctly replied
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.30 - Number of active entries test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        in_port,out_port, = openflow_ports(2)

        table_id = test_param_get("table",0)
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=0)
        logging.info("Sending flowmod msg")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        do_barrier(self.controller)

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)

        self.assertEqual(stats[table_id].active_count, 1, "Table stats active flow count is not correct")
        logging.info("Table stats active flow count is correct")



class Testcase_320_40_MultipartTableStatsLookupCount(base_tests.SimpleDataPlane):
    """
    320.40 -  /* Number of packets looked up in table. */
    Verify that the packets look_up number is correctly replied
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.40 - Number of packets looked up test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, no_port, out_port, = openflow_ports(3)
        table_id=0

        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                match= match,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                instructions=instructions,
                                priority=priority,
                                hard_timeout=0)
        logging.info("Sending flowmod msg")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        lookup_orig=stats[0].lookup_count

        match_pkt_no=5
        nonmatch_pkt_no=10

        for i in range(match_pkt_no):
        	pkt = str(simple_tcp_packet())
        	self.dataplane.send(in_port, pkt)
        	verify_packet(self, pkt, out_port)
        	logging.info("Sending matching dataplane packets")

        for i in range(nonmatch_pkt_no):
        	pkt = str(simple_tcp_packet())
        	self.dataplane.send(no_port, pkt)
        	verify_no_packet(self, pkt, out_port)
        	logging.info("Sending non-matching dataplane packets")

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        lookup_curr=stats[0].lookup_count
        
        time.sleep(2)
        self.assertEqual(lookup_curr-lookup_orig, match_pkt_no+nonmatch_pkt_no, "Table stats lookup count is not correct")

        logging.info("Table stats lookup count is correct")




class Testcase_320_50_MultipartTableStatsMatchedCount(base_tests.SimpleDataPlane):
    """
    320.50 -  /* Number of packets that hit table. */
    Verify that the matched_count number is correctly replied
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.50 - Number of packets test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, no_port, out_port, = openflow_ports(3)
        table_id=0

        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                match= match,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                instructions=instructions,
                                priority=priority,
                                hard_timeout=0)
        logging.info("Sending flowmod msg")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        matched_orig=stats[0].matched_count

        match_pkt_no=5
        nonmatch_pkt_no=10

        for i in range(match_pkt_no):
        	pkt = str(simple_tcp_packet())
        	self.dataplane.send(in_port, pkt)
        	verify_packet(self, pkt, out_port)
        	logging.info("Sending matching dataplane packets")

        for i in range(nonmatch_pkt_no):
        	pkt = str(simple_tcp_packet())
        	self.dataplane.send(no_port, pkt)
        	verify_no_packet(self, pkt, out_port)
        	logging.info("Sending non-matching dataplane packets")

        request = ofp.message.table_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        matched_curr=stats[0].matched_count
        
        time.sleep(2)
        self.assertEqual(matched_curr-matched_orig, match_pkt_no, "Table stats matched count is not correct")

        logging.info("Table stats matched count is correct")



class Testcase_320_60_MultipartTableFeatures(base_tests.SimpleDataPlane):
    """ 
    320.60 - OFPMP_TABLE_FEATURES multipart type allows a controller to both query for existing tables and ask the switch to reconfigure its tables
    Verify that the oft_multipart_reply returns correct information without error
    """ 

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.60 - OFPMP_TABLE_FEATURES multipart type test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        reply = get_stats(self, request)
        self.assertIsNotNone(reply, "Did not receive table stats reply.")
        logging.info("Received table stats reply as expected")

        request = ofp.message.table_features_stats_request(entries=reply)
        reply = get_stats(self, request)
        self.assertIsNotNone(reply, "Did not receive table features stats reply.")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPET_TABLE_FEATURES_FAILED, "Error code is not OFPET_TABLE_FEATURES_FAILED")
            logging.info("DUT does not support table features and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_TABLE_FEATURES,"Received table features reply as expected")
            logging.info("Received table features reply as expected")



class Testcase_320_70_MultipartTableFeaturesReply(base_tests.SimpleDataPlane):
    """
    320.70 - Table Features request and reply
    Verify that the table feature reply depends on the table feature request's body
	(if the request with none in body, the reply will be the current flow tables)
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.70 - Table Features request and reply test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        request = ofp.message.table_features_stats_request()
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")
        logging.info("Received table stats reply as expected")

        self.assertEqual(len(stats), tables_no, "Reported table number in table stats is not correct")
        logging.info("Reported table number in table stats is correct")



class Testcase_320_140_MultipartTableFeaturesUniqueID(base_tests.SimpleDataPlane):
    """
    320.140 - Table features unique id
    Verify that table features are reported for each table and that their table numbers are unique.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.140 - Table features unique id test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        request = ofp.message.table_features_stats_request()
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")
        logging.info("Received table stats reply as expected")

        self.assertEqual(len(stats), tables_no, "Reported table number in table stats is not correct")
        logging.info("Reported table number in table stats is correct")

        report_tables = []
        for item in stats:
            self.assertNotIn(item.table_id, report_tables, "Reported table id is not unique")
            report_tables.append(item.table_id)



class Testcase_320_150_MultipartTableFeaturesPropertyTypes(base_tests.SimpleDataPlane):
    """
    320.150 - Table features all property types
    Verify that all table feature prop types are reported for each table.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.150 - Table features all property types test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.table_features_stats_request()
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        for item in stats:
            reported_prop = []
            required_prop = []
            missing_prop = []

            for i in table_feature_prop.subtypes.keys()[:-2]:

                if i % 2 == 0:
                    required_prop.append(i)

            for prop in item.properties:
                reported_prop.append(prop.type)

            for prop in required_prop:
                if prop not in reported_prop:
                    missing_prop.append(prop)

        self.assertTrue(missing_prop == [], "Table feature prop types not reported: %s" % (missing_prop))
        logging.info("All table feature prop types are reported for each table")



class Testcase_320_190_MultipartTableFeaturesOrder(base_tests.SimpleDataPlane):
    """
    320.190 - Table features order
    Verify table features are reported from the lowest table number to the highest table number.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.190 - Table features order test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        self.assertEqual(len(stats), tables_no, "Table features stats is not correct")
        self.assertTrue(stats[0].table_id < stats[len(stats)-1].table_id, "Table ID is not in order")
        logging.info("Table features order is correct")



class Testcase_320_210_MultipartTableFeaturesMetadataMatch(base_tests.SimpleDataPlane):
    """
    320.210 - Table features metadata match
    Verify that if table features report support for matching on metadata, that the metadata_match field is not equal to zero.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.210 - Table features metadata match test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        table_id = 0

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")
        for reply in stats:
            if reply.table_id == table_id:
                for prop in reply.properties:
                    if prop.type == ofp.const.OFPTFPT_MATCH:
                        match = [m.value for m in prop.oxm_ids]
                        if ofp.oxm.metadata().type_len in match:
                            support = True
                        else:
                            support = False

        check = stats[0].metadata_match
        if support:
            self.assertTrue(check > 0, "Reported metadata match field is not correct")
            logging.info("DUT reported as expected")
        else:
            self.assertTrue(check == 0, "Reported metadata match field is not correct")
            logging.info("DUT reported as expected")



class Testcase_320_220_MultipartTableFeaturesMetadataWrite(base_tests.SimpleDataPlane):
    """
    320.220 - Table features metadata write
    Verify that if table features report support for writing metadata, that the metadata_write field is not equal to zero.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.220 - Table features metadata write test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_INSTRUCTIONS:
                check = [p.type for p in prop.instruction_ids]
                if ofp.const.OFPIT_WRITE_METADATA not in check:
                    logging.warn("Device does not support write metadata")
                    support = False
                else:
                    support = True
                    break
            elif prop.type == ofp.const.OFPTFPT_INSTRUCTIONS_MISS:
                check = [p.type for p in prop.instruction_ids]
                if ofp.const.OFPIT_WRITE_METADATA not in check:
                    logging.warn("Device does not support write metadata")
                    support = False
                else:
                    support = True
                    break

        check = stats[0].metadata_write
        if support:
            self.assertTrue(check > 0, "Reported metadata write field is not correct")
            logging.info("DUT reported as expected")
        else:
            self.assertTrue(check == 0, "Reported metadata write field is not correct")
            logging.info("DUT reported as expected")



class Testcase_320_230_MultipartTableFeaturesConfiguration(base_tests.SimpleDataPlane):
    """
    320.230 - Table features configuration
    Verify the config field of a table features message does not set invalid configuration bits.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.230 - Table features configuration test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        for item in stats:
            self.assertTrue(item.config == 0 or item.config == ofp.const.OFPTC_DEPRECATED_MASK, "Table features message set invalid configuration bits")

        logging.info("Received table features configuration as expected")



class Testcase_320_240_MultipartTableFeaturesMaxEntries(base_tests.SimpleDataPlane):
    """
    320.240 - Table features max entries
    Verify max_entries is reported correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.240 - Table features max entries test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        request = ofp.message.table_features_stats_request()
        stats = get_stats(testcase, req)
        self.assertIsNotNone(stats, "Did not receive table stats reply.")
        FlowMax = stats[0].max_entries

        in_port, out_port, = openflow_ports(2)
        priority = 1

        for i in range((FlowMax * 90) / 100):
            table_id=0
            priority = priority + 1
            actions=[ofp.action.output(port=out_port)]
            instructions=[ofp.instruction.apply_actions(actions=actions)]
            match = ofp.match([ofp.oxm.in_port(in_port)])
            request = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
            self.controller.message_send(req)
            verify_no_errors(self.controller)
            request = ofp.message.barrier_request()

        logging.info("Max_entries is reported correctly")

        time.sleep(10)
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        time.sleep(10)
        priority = 0
        for i in range((FlowMax * 90) / 100):
            table_id=0
            priority = priority + 1
            actions=[ofp.action.output(port=out_port)]
            instructions=[ofp.instruction.apply_actions(actions=actions)]
            match = ofp.match([
                    ofp.oxm.eth_type(0x0800),
                    ofp.oxm.ipv4_src(parse_ip("192.168.0.1")),
                    ofp.oxm.ipv4_dst(parse_ip("192.168.0.2"))
                ])
            request = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
            self.controller.message_send(req)
            verify_no_errors(self.controller)
            request = ofp.message.barrier_request()

        logging.info("Max_entries is reported correctly")



class Testcase_320_250_MultipartTableFeaturesReportedOrder(BII_testgroup320.Testcase_320_190_MultipartTableFeaturesOrder):
    """
    Tested in 320.190
    320.250 - Table features reported order
    Verify table features are reported from the lowest table number to the highest table number.
    """



class Testcase_320_270_MultipartTableFeaturesPropertyType(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.270 - Table features property type
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_280_MultipartTableFeaturesPropertyInstruction(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.280 - Table features property instruction
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_290_MultipartTableFeaturesPropertyInstructionMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.290 - Table features property instruction miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_300_MultipartTableFeaturesPropertyNextTables(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.300 - Table features property next tables
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_320_MultipartTableFeaturesPropertyWriteActions(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.320 - Table features property write actions
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_330_MultipartTableFeaturesPropertyWriteActionsMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.330 - Table features property write actions miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_340_MultipartTableFeaturesPropertyApplyActions(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.340 - Table features property apply actions
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_350_MultipartTableFeaturesPropertyApplyActionsMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.350 - Table features property apply actions miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_360_MultipartTableFeaturesPropertyMatch(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.360 - Table features property match
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_370_MultipartTableFeaturesPropertyWildcards(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.370 - Table features property wildcards
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_380_MultipartTableFeaturesPropertyWriteSetField(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.380 - Table features property write set field
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_390_MultipartTableFeaturesPropertyWriteSetFieldMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.390 - Table features property write set field miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_400_MultipartTableFeaturesPropertyWriteApplySetField(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.400 - Table features property apply set field
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_410_MultipartTableFeaturesPropertyWriteApplySetFieldMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.410 - Table features property apply set field miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_420_MultipartTableFeaturesPropertyExperimenter(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.420 - Table features property experimenter
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_430_MultipartTableFeaturesPropertyExperimenterMiss(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    Tested in 320.150
    320.430 - Table features property experimenter miss
    Verify that all table feature prop types are reported for each table.
    """



class Testcase_320_440_MultipartTableFeaturesPropertyMissSuffix(base_tests.SimpleDataPlane):
    """
    320.440 - Table features property miss suffix
    Verify that all table feature prop types are reported for each table.
    Tested in testgroup 330
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.440 - Table features property miss suffix test")
        logging.info("Tested in group 330")


class Testcase_320_450_MultipartTableFeaturesProperyEmptyList(BII_testgroup320.Testcase_320_150_MultipartTableFeaturesPropertyTypes):
    """
    320.450 - Table features property empty list
    Verify that all table feature prop types are reported for each table.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.450 - Table features property empty list test")
        logging.info("Tested in group 330")

        

class Testcase_320_460_MultipartTableFeaturesPropertyExperimenterMiss(base_tests.SimpleDataPlane):
    """
    320.460 - Table features property omoited property
    Verify that all table feature prop types are reported for each table.
    Tested in testgroup 330
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.460 - Table features property omoited property test")
        logging.info("Tested in group 330")



class Testcase_320_470_MultipartTableFeaturesPropertyRequiredInstructions(base_tests.SimpleDataPlane):
    """
    320.470 - Table features property required instructions
    Verify all require instructions are supported.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.470 - Table features property required instructions test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        supported_instructions = []
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_INSTRUCTIONS:
                supported_instructions = [p.type for p in prop.instruction_ids]
            elif prop.type == ofp.const.OFPTFPT_INSTRUCTIONS_MISS:
                supported_instructions = [p.type for p in prop.instruction_ids]
                
        for i in [1,3]:
            self.assertIn(i, supported_instructions,"Not all required instructions are supported")

        logging.info("All required instructions are supported as expected.")



class Testcase_320_480_MultipartTableFeaturesPropertyNextTables(base_tests.SimpleDataPlane):
    """
    320.480 - Table features property next tables
    Verify the next_tables_id field correctly reports all table ids.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.480 - Table features property next tables test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")

        next_tables = None
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_NEXT_TABLES:
                next_tables = prop
                self.assertIsNotNone(next_tables, "DUT did not report the next tables property.")

        if len(stats) == 1:
            self.assertEqual(next_tables.next_table_ids, [], "The next_tables_id field incorrectly reported")
        else:
            self.assertTrue(len(next_tables.next_table_ids) > 0, "The next_tables_id field incorrectly reported")

        logging.info("The next_tables_id field correctly reports all table ids")



class Testcase_320_500_MultipartTableFeaturesPropertyWriteActionsMiss(base_tests.SimpleDataPlane):
    """
    320.500 - Table features property write actions miss
    Verify all reported actions can be used with the write actions instruction on table miss entries.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.500 - Table features property write actions miss test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")      
        
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_WRITE_ACTIONS:
                instruction = prop
            elif prop.type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
                instruction = prop

        self.assertIsNotNone(instruction, "NO reported actions found")



class Testcase_320_510_MultipartTableFeaturesPropertyApplyActions(base_tests.SimpleDataPlane):
    """
    320.510 - Table features property apply actions
    Verify all reported actions can be used with the apply actions instruction.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.510 - Table features property apply actions test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")      
        
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_APPLY_ACTIONS:
                action = prop
            else:
                action = None

        self.assertIsNotNone(action, "NO reported actions found")



class Testcase_320_520_MultipartTableFeaturesPropertyApplyActionsMiss(base_tests.SimpleDataPlane):
    """
    320.520 - Table features property apply actions miss
    Verify all reported actions can be used with the apply actions instruction on table miss entries.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 320.520 - Table features property apply actions miss test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        logging.info("Sending table stats request")
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")      
        
        for prop in stats[0].properties:
            if prop.type == ofp.const.OFPTFPT_APPLY_ACTIONS:
                action = prop
            elif prop.type == ofp.const.OFPTFPT_APPLY_ACTIONS_MISS:
                action = prop

        self.assertIsNotNone(action, "NO reported actions found")