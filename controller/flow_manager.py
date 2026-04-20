"""OpenFlow 1.3 helper functions for allow and deny rules."""

from __future__ import annotations


class FlowManager:
    """Wraps flow installation details to keep the controller concise."""

    TABLE_MISS_PRIORITY = 0
    ALLOW_PRIORITY = 100
    DENY_PRIORITY = 200

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(flow_mod)

    def add_drop_flow(self, datapath, source_mac):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=source_mac)
        self.add_flow(datapath, self.DENY_PRIORITY, match, [])

    def add_allow_flow(self, datapath, in_port, source_mac, destination_mac, out_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=source_mac,
            eth_dst=destination_mac,
        )
        actions = [parser.OFPActionOutput(out_port)]
        idle_timeout = 60 if out_port != ofproto.OFPP_FLOOD else 15
        self.add_flow(
            datapath,
            self.ALLOW_PRIORITY,
            match,
            actions,
            idle_timeout=idle_timeout,
            hard_timeout=0,
        )

    def install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(datapath, self.TABLE_MISS_PRIORITY, match, actions)

    @staticmethod
    def build_packet_out(datapath, buffer_id, in_port, actions, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        packet_data = data if buffer_id == ofproto.OFP_NO_BUFFER else None
        return parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=packet_data,
        )


def flow_intent_for_source(authorized_macs, source_mac):
    """Simple helper used by regression tests."""

    normalized_authorized = {mac.lower() for mac in authorized_macs}
    normalized_source = source_mac.lower()
    if normalized_source in normalized_authorized:
        return "ALLOW"
    return "DENY"
