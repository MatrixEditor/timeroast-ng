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
# Description:
#   This script allows you to get the SID, sAMAccountName and dNSHostName of
#   a computer account on a domain controller using its RID.
#
# Author:
#   MatrixEditor
# ----------------------------------------------------------------------------
# This tool is based on lookupsid, part of Impacket
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#   Alberto Solino (@agsolino)
# ----------------------------------------------------------------------------
import argparse
import logging
import sys
import traceback

from impacket import version
from impacket.ntlm import NTLM_AUTH_PKT_PRIVACY
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, RPC_SID, SID
from impacket.ldap import ldap

from impacket.examples import logger
from impacket.examples.utils import parse_target

# modified version of impacket/examples/lookupsid.py
class LSADomainSid:

    KNOWN_PORTS = {
        139: {"bindstr": r"ncacn_np:%s[\pipe\lsarpc]", "set_host": True},
        445: {"bindstr": r"ncacn_np:%s[\pipe\lsarpc]", "set_host": True},
    }

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        port: int | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        use_enryption: bool = False,
    ) -> None:
        self.username = username or ""
        self.password = password or ""
        self.domain = domain or ""
        self.port = port or 139
        self.lmhash, self.nthash = "", ""
        self.use_kerberos = use_kerberos
        if hashes is not None:
            # we assume the string is formatted correctly
            self.lmhash, self.nthash = hashes.split(":")
        self.use_encryption = use_enryption

    def get_domain_sid(self, remote_name: str, remote_host: str) -> RPC_SID | None:
        logging.info("Fetching domain SID from %s", remote_name)

        if self.port not in LSADomainSid.KNOWN_PORTS:
            logging.error(
                "Invalid port configuration - expected either 139 or 445, got %s",
                self.port,
            )
            return

        binding = LSADomainSid.KNOWN_PORTS[self.port]["bindstr"] % remote_name
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.set_dport(self.port)
        rpc_transport.set_kerberos(self.use_kerberos)
        rpc_transport.setRemoteHost(remote_host)

        logging.info("Connecting using StrBinding: %s", binding)
        rpc_transport.set_credentials(
            self.username, self.password, self.domain, self.lmhash, self.nthash
        )
        try:
            return self._fetch_sid(rpc_transport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            # only string representation here
            logging.critical(str(e))

    def _fetch_sid(self, rpc_transport: transport.DCERPCTransport) -> RPC_SID:
        dce = rpc_transport.get_dce_rpc()
        dce.connect()

        if self.use_encryption:
            dce.set_auth_level(NTLM_AUTH_PKT_PRIVACY)

        dce.bind(lsat.MSRPC_UUID_LSAT)
        policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
        policyHandle = policy["PolicyHandle"]

        information_policy = lsad.hLsarQueryInformationPolicy2(
            dce,
            policyHandle,
            lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation,
        )
        sid = information_policy["PolicyInformation"]["PolicyPrimaryDomainInfo"]["Sid"]
        logging.info("Domain Sid is: %s", sid.formatCanonical())
        dce.disconnect()
        return sid

# shamelessly copied and modified from impacket examples
def ldap_login(argv, lookup: LSADomainSid, remote_name: str) -> ldap.LDAPConnection:
    base_dn_parts = domain.split(".")
    base_dn = ",".join([f"dc={x}" for x in base_dn_parts])
    try:
        ldapConnection = ldap.LDAPConnection(
            "ldap://%s" % remote_name,
            base_dn,
            argv.dc_ip,
        )
        if not lookup.use_kerberos:
            ldapConnection.login(
                lookup.username,
                lookup.password,
                lookup.domain,
                lookup.lmhash,
                lookup.nthash,
            )
        else:
            ldapConnection.kerberosLogin(
                lookup.username,
                lookup.password,
                lookup.domain,
                lookup.lmhash,
                lookup.nthash,
                kdcHost=argv.dc_ip,
            )
        return ldapConnection
    except ldap.LDAPSessionError as e:
        if str(e).find("strongerAuthRequired") >= 0:
            # We need to try SSL
            ldapConnection = ldap.LDAPConnection(
                "ldaps://%s" % remote_name,
                base_dn,
                argv.dc_ip,
            )
            if lookup.use_kerberos is not True:
                ldapConnection.login(
                    lookup.username,
                    lookup.password,
                    lookup.domain,
                    lookup.lmhash,
                    lookup.nthash,
                )
            else:
                ldapConnection.kerberosLogin(
                    lookup.username,
                    lookup.password,
                    lookup.domain,
                    lookup.lmhash,
                    lookup.nthash,
                    kdcHost=argv.dc_ip,
                )
            return ldapConnection
        else:
            if str(e).find("NTLMAuthNegotiate") >= 0:
                logging.critical(
                    "NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                    "authentication instead."
                )
            else:
                if argv.dc_ip is not None:
                    logging.critical(
                        "If the credentials are valid, check the hostname and IP address of KDC. They "
                        "must match exactly each other."
                    )
            raise


if __name__ == "__main__":
    print(version.BANNER)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "rid",
        action="store",
        help="User or Computer relative identifier (RID)",
    )
    parser.add_argument(
        "-ts",
        action="store_true",
        help="Adds timestamp to every logging output",
    )
    parser.add_argument(
        "-domain-sid",
        action="store",
        type=str,
        help="Target Domain SID to use (won't try to resolve)."
    )

    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target domain controller. "
        "If omitted it will use whatever was specified as target. This is useful when target is the "
        "NetBIOS name and you cannot resolve it",
    )
    conn_group.add_argument(
        "-port",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="Destination port to connect to SMB Server",
    )
    conn_group.add_argument(
        "-encrypt",
        action="store_true",
        help="Uses encryption when connecting to the RPC target.",
    )

    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    auth_group.add_argument(
        "-no-pass",
        action="store_true",
        help="don't ask for password (useful when proxying through smbrelayx)",
    )
    auth_group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )

    argv = parser.parse_args()
    logger.init(argv.ts)

    domain, username, password, remote_name = parse_target(argv.target)
    if not password and not username and not argv.hashes and not argv.no_pass:
        from getpass import getpass

        password = getpass("Password:")

    if not argv.dc_ip:
        argv.dc_ip = remote_name

    lookup = LSADomainSid(
        username,
        password,
        domain,
        int(argv.port),
        argv.hashes,
        argv.k,
        argv.encrypt,
    )
    if not argv.domain_sid:
        sid = lookup.get_domain_sid(remote_name, argv.dc_ip)
        if sid is None:
            sys.exit(1)

        argv.domain_sid = sid.formatCanonical()

    # append RID to resolve computer or user
    user_sid_canonical = f"{argv.domain_sid}-{argv.rid}"
    user_sid = SID()
    user_sid.fromCanonical(user_sid_canonical)
    logging.info("User SID: %s", user_sid_canonical)

    # try connecting over ldap

    ldap_conn = ldap_login(argv, lookup, remote_name)
    search_filter = f"(&(objectSid={user_sid.formatCanonical()}))"
    entries = ldap_conn.search(
        searchFilter=search_filter,
        attributes=["sAMAccountName", "dNSHostName"],
    )

    if len(entries) == 0:
        logging.error("User/Computer with target SID not found!")
        sys.exit(1)

    computer = entries[0]
    account_name = None
    dns_name = None
    for attribute in computer["attributes"]:
        match str(attribute["type"]):
            case "sAMAccountName":
                account_name = str(attribute["vals"][0])
            case "dNSHostName":
                dns_name = str(attribute["vals"][0])

    logging.info("sAMAccountName: %s", account_name)
    if dns_name:
        logging.info("dNSHostName: %s", dns_name)
    ldap_conn.close()
