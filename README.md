Get IP Tables Command-Line Utility
==================================

Dumps information about Windows TCP/IP and UDP/IP tables (both IPv4 and IPv6) as JSON.  Released under a MIT or LGPL license.

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/) [![Discord](https://img.shields.io/discord/777282089980526602?label=chat&logo=discord)](https://cubiclesoft.com/product-support/github/)

Features
--------

* Command-line action!
* Dumps the results of the GetTcpTable2(), GetTcp6Table2(), GetUdpTable(), and GetUdp6Table() Windows APIs as JSON.  Easily consumed by most programming and scripting languages.
* Pre-built binaries using Visual Studio (statically linked C++ runtime, minimal file size of ~117K, direct Win32 API calls).
* Windows subsystem variant.
* Unicode support.
* Has a liberal open source license.  MIT or LGPL, your choice.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Useful Information
------------------

Running the command with the `/?` option will display the options:

```
(C) 2021 CubicleSoft.  All Rights Reserved.

Syntax:  getiptables.exe [options]

Options:
        /v
        Verbose mode.

        /tcponly
        Only output TCP table information.
        Incompatible with 'udponly'.

        /udponly
        Only output UDP table information.
        Incompatible with 'tcponly'.

        /state=State
        Only output table information for the specified state.
        Map only be one of:
                CLOSED
                LISTEN
                SYN-SENT
                SYN-RECEIVED
                ESTABLISHED
                FIN-WAIT-1
                FIN-WAIT-2
                CLOSE-WAIT
                CLOSING
                LAST-ACK
                TIME-WAIT
                DELETE-TCB

        /localip=IPAddr
        Only output table information for the specified local IP address.

        /localport=PortNum
        Only output table information for the specified local port number.

        /remoteip=IPAddr
        Only output table information for the specified remote IP address.

        /remoteport=PortNum
        Only output table information for the specified remote port number.

        /sort
        Sort the output.

        /file=OutputFile
        File to write the JSON output to instead of stdout.
```

Example usage:

```
C:\>getiptables /tcponly /state=ESTABLISHED /localip=127.0.0.1
{"success": true, "tcp4": {"success": true, "info": [{"state": "ESTABLISHED", "local_ip": "127.0.0.1", "local_port": 49767, "remote_ip": "127.0.0.1", "remote_port": 49768, "pid": 704, "offload_state": "InHost"},

{"state": "ESTABLISHED", "local_ip": "127.0.0.1", "local_port": 49768, "remote_ip": "127.0.0.1", "remote_port": 49767, "pid": 704, "offload_state": "InHost"}]},

"tcp6": {"success": true, "info": []}}
```
