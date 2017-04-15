package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by cetho on 4/14/2017.
 */
public class StatelessPolicy extends Policy {

    //Protocol
    public Protocol protocol = Protocol.Any;

    public StatelessPolicy() {
        isStateful = false;
    }

    public boolean packetMatchesPolicy(PcapPacket packet) {

        boolean isTcp = false;
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        Payload payload = new Payload();
        Udp udp = new Udp();
        //Get relevant headers.
        packet.getHeader(ip4);

        //Create UDP or TCP header if it matches our rules.
        if(packet.hasHeader(Tcp.ID)) {
            isTcp = true;
            packet.getHeader(tcp);
            if(this.protocol != Protocol.TCP) {
                //This packet is the wrong protocol. It can't possibly match.
                return false;
            }

        } else if(packet.hasHeader(Udp.ID)) {
            packet.getHeader(udp);
            if(this.protocol != Protocol.UDP) {
                //This packet is the wrong protocol. It can't possibly match.
                return false;
            }
        } else {
            //Not a packet we care about.
            return false;
        }


        //Check if packet is to the host or from the host.
        if(packetIsToHost(ip4)) {
            if(isTcp) {
                //Check if host ports match.
                if (!hostPortMatches(tcp.destination())) {
                    //Different Ports. No match.
                    return false;
                }
                //Check if attacker ports match.
                if (!attackerPortMatches(tcp.source())) {
                    //Different Ports. No match.
                    return false;
                }
            } else {
                //Check if host ports match.
                if (!hostPortMatches(udp.destination())) {
                    //Different Ports. No match.
                    return false;
                }
                //Check if attacker ports match.
                if (!attackerPortMatches(udp.source())) {
                    //Different Ports. No match.
                    return false;
                }
            }
            if(!packetMatchesAttacker(ip4.source())) {
                return false;
            }
            //Check if the payload matches a to-host rule.
            if(packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                return payloadMatch(payload, this.to_host);
            }
        } else if (packetIsFromHost(ip4)) {
            if(isTcp) {
                //Check if host ports match.
                if (!hostPortMatches(tcp.source())) {
                    //Different Ports. No match.
                    return false;
                }
                //Check if attacker ports match.
                if (!attackerPortMatches(tcp.destination())) {
                    //Different Ports. No match.
                    return false;
                }
            } else {
                //Check if host ports match.
                if (!hostPortMatches(udp.source())) {
                    //Different Ports. No match.
                    return false;
                }
                //Check if attacker ports match.
                if (!attackerPortMatches(udp.destination())) {
                    //Different Ports. No match.
                    return false;
                }
            }
            //Check attacker IP.
            if(!packetMatchesAttacker(ip4.destination())) {
                return false;
            }
            if(packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                return payloadMatch(payload, this.from_host);
            }
        }
        return false;
    }

    private boolean hostPortMatches(int port) {
        if(this.host_port == -1 || this.host_port == port) {
            //Different Ports. No match.
            return true;
        } else {
            return false;
        }
    }

    private boolean attackerPortMatches(int port) {
        if(this.attacker_port == -1 || this.attacker_port == port) {
            //Different Ports. No match.
            return true;
        } else {
            return false;
        }
    }
}