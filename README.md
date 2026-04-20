# SDN-Based Access Control System

This project uses a Ryu SDN controller and a Mininet topology to enforce host-level access control with OpenFlow 1.3.

The controller maintains a whitelist of authorized hosts, installs allow or deny flow rules dynamically, and exposes simple verification and regression-testing workflows.

## Project Structure

```text
sdn-access-control/
├── config/
│   └── whitelist.json
├── controller/
│   ├── __init__.py
│   ├── access_controller.py
│   ├── flow_manager.py
│   └── whitelist_manager.py
├── tests/
│   ├── __init__.py
│   └── test_policy.py
└── topology/
    └── access_topology.py
```

## Architecture

### 1. How SDN Works In This Project

Software Defined Networking separates the control plane from the data plane:

- The Open vSwitch instance in Mininet forwards packets.
- The Ryu controller decides which traffic should be allowed or denied.
- OpenFlow 1.3 messages carry rules from the controller to the switch.

This project implements access control by checking the source MAC address of a host against a whitelist. Authorized hosts receive forwarding rules. Unauthorized hosts receive drop rules.

### 2. Controller, Switch, and Hosts Interaction

1. Hosts in Mininet send traffic through a single OpenFlow switch.
2. If the switch does not already have a matching rule, it sends a `PacketIn` event to the Ryu controller.
3. The controller learns the host location and checks whether the source MAC is whitelisted.
4. The controller installs one of these rules:
   - Allow rule: traffic from an authorized source is forwarded toward the destination or flooded until the destination is learned.
   - Deny rule: traffic from an unauthorized source is matched and dropped.
5. Subsequent packets follow the installed flow entry directly on the switch without controller intervention.

### 3. Flow Rule Logic

#### Allow Rule

Installed when:

- Source MAC is present in the whitelist.
- Destination is known or traffic should be temporarily flooded.

Match fields:

- `in_port`
- `eth_src`
- `eth_dst`

Action:

- `OUTPUT:<port>` for known destinations
- or `FLOOD` for unknown destinations

Priority:

- Higher than the table-miss rule

#### Deny Rule

Installed when:

- Source MAC is not present in the whitelist

Match fields:

- `eth_src`

Action:

- No action, so the switch drops matching packets

Priority:

- Higher than allow rules to make blocking deterministic for unauthorized senders

### 4. Policy Model Used Here

The whitelist is stored in `config/whitelist.json`:

```json
{
  "authorized_hosts": [
    "00:00:00:00:00:01",
    "00:00:00:00:00:02",
    "00:00:00:00:00:03"
  ]
}
```

In the default topology:

- Authorized: `h1`, `h2`, `h3`
- Unauthorized: `h4`, `h5`, `h6`

That means:

- `h1`, `h2`, `h3` are allowed to initiate communication.
- `h4`, `h5`, `h6` are blocked when they try to send packets.

## Installation Guide

These steps assume Ubuntu, Ubuntu in WSL2 with a Linux networking-capable setup, or a Linux VM.

### 1. System Packages

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv mininet openvswitch-switch openvswitch-testcontroller
```

If `openvswitch-switch` is not already active:

```bash
sudo systemctl restart openvswitch-switch
sudo systemctl enable openvswitch-switch
```

### 2. Install Ryu

Use a virtual environment to avoid Python package conflicts:

```bash
cd /home/aditya/sdn-access-control
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install ryu
```

### 3. Confirm Tools

```bash
mn --version
ovs-vsctl --version
ryu-manager --version
```

## Files To Run

### Ryu Controller

File:

- `controller/access_controller.py`

Responsibilities:

- Reads the whitelist
- Handles `PacketIn` events
- Installs allow and deny flow entries
- Logs policy decisions

### Mininet Topology

File:

- `topology/access_topology.py`

Responsibilities:

- Builds a single-switch topology with six hosts
- Labels authorized and unauthorized hosts through deterministic MAC/IP assignments
- Connects to the remote Ryu controller

## Execution Instructions

Open three terminals.

### Terminal 1: Start the Ryu Controller

```bash
cd /home/aditya/sdn-access-control
source .venv/bin/activate
ryu-manager controller/access_controller.py
```

Expected output includes lines similar to:

```text
loading app controller/access_controller.py
instantiating app controller/access_controller.py of AccessControlController
Whitelist loaded with 3 authorized host(s)
Switch 1 connected; installing table-miss flow
```

### Terminal 2: Start Mininet Topology

```bash
cd /home/aditya/sdn-access-control
sudo python3 topology/access_topology.py
```

Expected output includes:

```text
*** Creating network
*** Adding controller
*** Adding hosts
*** Starting network
```

### Terminal 3: Optional Flow Inspection

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

You should see:

- a table-miss entry
- allow rules after authorized traffic is generated
- drop rules after unauthorized traffic is generated

## Verification Procedure

Start with Mininet CLI after the topology launches.

### 1. Show Host Addresses

Inside Mininet:

```bash
nodes
dump
```

### 2. Verify Authorized Hosts Can Communicate

```bash
mininet> h1 ping -c 2 h2
mininet> h2 ping -c 2 h3
```

Expected result:

- Ping succeeds
- Controller logs show `ALLOW`

### 3. Verify Unauthorized Hosts Are Blocked

```bash
mininet> h4 ping -c 2 h1
mininet> h5 ping -c 2 h2
```

Expected result:

- Ping fails
- Controller logs show `DENY`
- Flow dump shows a drop rule matching the unauthorized source MAC

### 4. Dump Installed Rules

On the Linux shell:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Look for:

- allow flows such as `eth_src=00:00:00:00:00:01`
- drop flows such as `eth_src=00:00:00:00:00:04`

## Dynamic Policy Update Workflow

The whitelist can be modified live by editing `config/whitelist.json`.

Example: authorize `h4`

```json
{
  "authorized_hosts": [
    "00:00:00:00:00:01",
    "00:00:00:00:00:02",
    "00:00:00:00:00:03",
    "00:00:00:00:00:04"
  ]
}
```

Then:

1. Re-run traffic from `h4`.
2. The controller reloads the whitelist on each packet decision.
3. New traffic from `h4` is allowed.

To observe a clean transition, remove old switch rules first:

```bash
sudo ovs-ofctl -O OpenFlow13 del-flows s1
```

Then restart the controller or let it reinstall the table-miss flow by restarting Mininet and Ryu.

Recommended clean restart:

```bash
sudo mn -c
```

Then relaunch the controller and topology.

## Regression Testing

The tests validate:

- authorized hosts are recognized correctly
- newly added hosts become authorized
- removed hosts lose authorization
- generated policy intents do not produce conflicting allow and deny decisions for the same host

Run:

```bash
cd /home/aditya/sdn-access-control
python3 -m unittest discover -s tests -v
```

Expected output:

```text
test_add_host_to_whitelist ... ok
test_conflicting_policy_is_rejected ... ok
test_default_authorization ... ok
test_remove_host_from_whitelist ... ok
```

## Exact End-To-End Command Order

```bash
cd /home/aditya
mkdir -p sdn-access-control
cd sdn-access-control
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install ryu
sudo apt update
sudo apt install -y mininet openvswitch-switch
source .venv/bin/activate
ryu-manager controller/access_controller.py
```

In another terminal:

```bash
cd /home/aditya/sdn-access-control
sudo python3 topology/access_topology.py
```

In Mininet CLI:

```bash
h1 ping -c 2 h2
h4 ping -c 2 h1
```

In another shell:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
python3 -m unittest discover -s tests -v
```

## Optional Enhancements

1. REST API
   - Use Ryu WSGI support to add endpoints for `GET /whitelist`, `POST /whitelist`, and `DELETE /whitelist/<mac>`.
2. CLI tool
   - Add a Python utility that edits `whitelist.json` safely.
3. Persistent logging
   - Write policy decisions to a file for audit analysis.
4. Periodic reconciliation
   - Re-scan switch flows and remove stale entries after policy changes.
5. Multi-switch support
   - Extend topology and controller logic to enforce the same whitelist across several switches.
