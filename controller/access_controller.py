"""Ryu controller application implementing SDN-based access control."""

from __future__ import annotations

import os
import sys

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(CURRENT_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from controller.flow_manager import FlowManager
from controller.whitelist_manager import PolicyEngine, WhitelistManager


class AccessControlController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        whitelist_path = os.path.join(base_dir, "config", "whitelist.json")

        self.mac_to_port = {}
        self.flow_manager = FlowManager()
        self.whitelist_manager = WhitelistManager(whitelist_path)
        self.policy_engine = PolicyEngine(self.whitelist_manager)

        self.logger.info(
            "Whitelist loaded with %d authorized host(s): %s",
            len(self.whitelist_manager.get_all()),
            sorted(self.whitelist_manager.get_all()),
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self.flow_manager.install_table_miss(datapath)
        self.logger.info(
            "Switch %s connected; installing table-miss flow",
            datapath.id,
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP and IPv6 control traffic so the demo logs stay focused on
        # whitelist enforcement for ordinary host-to-host communication.
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dst = eth.dst.lower()
        src = eth.src.lower()
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        decision = self.policy_engine.decide(src)

        if decision == PolicyEngine.ACTION_DENY:
            self.flow_manager.add_drop_flow(datapath, src)
            self.logger.warning(
                "DENY src=%s dst=%s in_port=%s switch=%s",
                src,
                dst,
                in_port,
                dpid,
            )
            return

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        self.flow_manager.add_allow_flow(
            datapath=datapath,
            in_port=in_port,
            source_mac=src,
            destination_mac=dst,
            out_port=out_port,
        )

        packet_out = self.flow_manager.build_packet_out(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(packet_out)
        self.logger.info(
            "ALLOW src=%s dst=%s in_port=%s out_port=%s switch=%s",
            src,
            dst,
            in_port,
            out_port,
            dpid,
        )
