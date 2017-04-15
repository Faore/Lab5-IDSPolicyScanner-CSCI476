package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * Created by cetho on 4/14/2017.
 */
public class StatefulPolicy extends Policy {

    public StatefulPolicy() {
        isStateful = true;
    }

    public boolean packetMatchesPolicy(PcapPacket packet) {
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        Payload payload = new Payload();
        //Get relevant headers.
        packet.getHeader(ip4);
        packet.getHeader(tcp);


        //Check if packet is to the host or from the host.
        if (packetIsToHost(ip4)) {
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
            if (!packetMatchesAttacker(ip4.source())) {
                return false;
            }
            //Check if the payload matches a to-host rule.
            if (packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                return payloadMatch(payload, this.to_host);
            }
        } else if (packetIsFromHost(ip4)) {
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
            //Check attacker IP.
            if (!packetMatchesAttacker(ip4.destination())) {
                return false;
            }
            if (packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                return payloadMatch(payload, this.from_host);
            }
        }
        return false;
    }
}
