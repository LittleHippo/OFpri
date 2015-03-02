# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 10 verifies establishment of a control channel, version negotiation, 
and device behavior when the control channel is lost.

To satisfy basic conformance an OpenFlow enabled device must pass at least one of 
10.30, 10.40, 10.50 and 10.20, or 10.60 and 10.20. Additionally a device must pass 
either 10.110 and 10.130, or 10.120. For basic conformance test cases 10.10, and 
10.70 - 10.100 must be passed by all devices.
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

from oftest.oflog import *
from oftest.testutils import *
from time import sleep


class Testcase_10_10_StartupBehavior(base_tests.DataPlaneOnly):
    """
    10.10 - Startup behavior without established control channel
    Startup from factory default mode. Expected behavior should be as defined in the switch documentation.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.10 - Startup behavior without established control channel test")
        port1, = openflow_ports(1)
        data = simple_arp_packet()
        logging.info("Sending dataplane packet")
        self.dataplane.send(port1, str(data))
        verify_packets(self, data, [])
        logging.info("No packet has been forworded as expected")
        
   

class Testcase_10_70_VersionNegotiationSuccess(base_tests.SimpleProtocol):
    """
    10.70 - Version negotiation on version field success
    Check that the switch negotiates the correct version with the controller, based on the version field.
    """

    def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        self.controller.start()

        try:
            self.controller.connect(timeout=20)
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.70 - Version negotiation on version field success test")
        timeout = 60
        nego_version = 4
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Hello msg')
        self.assertEqual(rv.version,nego_version, 'Received version of Hello msg is not 4')
        logging.info("Received Hello msg with correct version")
        reply = ofp.message.hello()
        reply.version=nego_version
        self.controller.message_send(reply)
        logging.info("Sending Hello msg with version 4")
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        self.assertEqual(rv.version,nego_version, 'Received version of Hello msg is not 4')
        logging.info("Received echo reply with correct version")

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)



class Testcase_10_30_TCPdefaultPort(base_tests.SimpleProtocol):
    """
    10.30 - TCP default Port
    Test unencrypted control channel establishment on default port
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.30 - TCP default Port test")
        timeout = 5
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        logging.info("Received echo reply with default port")




class Testcase_10_80_VersionNegotiationFailure(base_tests.SimpleProtocol):
    """
    10.80 - Version negotiation failure
    Verify correct behavior in case of version negotiation failure.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.80 - Version negotiation failure test")
        timeout = 5
        nego_version = 0
        logging.info("Received Hello msg with correct version")
        request = ofp.message.hello()
        request.version=nego_version
        self.controller.message_send(request)
        logging.info("Sending Hello msg with version 0")
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Error msg')
        self.assertEqual(rv.err_type,ofp.const.OFPET_HELLO_FAILED, " Error type is not correct. Expect error type: OFPET_HELLO_FAILED")
        logging.info("Received OFPET_HELLO_FAILED")
        self.assertEqual(rv.code, ofp.const.OFPHFC_INCOMPATIBLE, "Error Code is not correct. Expect error code: OFPHFC_INCOMPATIBLE")
        logging.info("Received Error code is OFPHFC_INCOMPATIBLE")

        
        
class Testcase_10_90_VersionNegotiationBitmap(base_tests.SimpleProtocol):
    """
    10.90 - 10.90 - Version negotiation based on bitmap
    Verify that version negotiation based on bitmap is successful
    """

    def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        self.controller.start()

        try:
            self.controller.connect(timeout=20)
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.90 - Version negotiation based on bitmap test")
        timeout = 60
        version = 1
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Hello msg')
        self.assertEqual(rv.version,version, 'Received version of Hello msg is not 4')
        logging.info("Received Hello msg with correct version")
        reply = ofp.message.hello()
        reply.version=version
        bitmap = ofp.common.uint32(0x16) # 10110
        hello_elem = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap])
        req.elements.append(hello_elem)
        self.controller.message_send(reply)
        logging.info("Sending Hello msg with bitmap")
        self.assertTrue(res.elements != [], 'Hello msg does not include Bitmap')
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        self.assertEqual(rv.version,version, 'Received version of Hello msg is not 4')
        logging.info("Version negotiation Success")

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)

