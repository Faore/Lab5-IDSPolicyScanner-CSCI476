# CSCI476 - Lab 5: IDS Policy Scanner
This IDS implementation takes 2 arguments in the following order:
 - Path to a policy file
 - Path to a Pcap capture file

## Dependencies
Built using jNetPcap 1.3.0 (Production/Stable) on JDK 1.8.

## How Packets and Sessions Are Matched
### Stateless
In a stateless policy each packet is matched individually.

For each packet, the protocol, hosts and ports are matched according to the policy.
If the packet is sent _to_ the host, the ``to_host`` sub-policies are used, 
otherwise the ``from_host`` policies are used.
The sub-policies use regular expressions to match the entirety of the packet sent to or from the host, 
not just the payload at the end of the packet. This allows the packet handler to match information such as flags,
and TCP options in the regular expression.
### Stateful
TCP sessions are captured between 2 peers, identified by tracking their addresses and ports. The session's packets are 
stored in two seperate lists: one for packets sent to a peer, and one for packets recieved from the peer. At the end of 
the capture, the session is analyzed as a whole, associating the host and attacker to the session peers. If associated, 
 the proper sub-policy is applied via regular expression, but on the full contents of all packets to or from a host
 (depending on the policy, "from" or "to") concatenated together.

## Policy Format
A policy must be of the following format to be parsed correctly:
````
<file> ::= <host><policy>*

<host> ::= host=<ip>\n\n

<policy> ::= name=<string>\n
    <(stateful_policy >|<stateless_policy)>\n

<stateful_policy> ::= type=stateful\n
    host_port=(any|<port>)\n
    attacker_port=(any|<port>)\n
    attacker=(any|<ip>)\n
    (from_host|to_host)=<regexp>\n

<stateless_policy> ::= type=stateless\n
    proto=tcp|udp\n
    host_port=(any|<port>)\n
    attacker_port=(any|<port>)\n
    attacker=(any|<ip>)\n
    <sub_policy>
    <sub_policy>*

<sub_policy> ::= (from_host|to_host)=<regexp> (with flags=<flags>)?\n

<string> ::= alpha-numeric string

<ip> ::= string of form [0-255].[0-255].[0-255].[0-255]

<port> ::= string of form [0-65535]

<regexp> ::= Regular Expression
````