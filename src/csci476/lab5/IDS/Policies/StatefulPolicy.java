package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import csci476.lab5.IDS.TCPSession;
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
        //Don't use.
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

    public boolean sessionMatchesPolicy(TCPSession session) {
        int hostPeer = 0;
        // Associate host to peer.
        if(session.peer1Addr.equals(this.host_address)) {
            hostPeer = 1;
        } else if(session.peer2Addr.equals(this.host_address)) {
            hostPeer = 2;
        }
        //The host isn't involved in this session, it can't match.
        if(hostPeer == 0) {
            return false;
        }
        //Lets make sure that the attacker matches
        if(hostPeer == 1) {
            if(!(this.attacker_address.equals("any") || this.attacker_address.equals(session.peer2Addr))) {
                return false;
            }
        }
        if(hostPeer == 2) {
            if(!(this.attacker_address.equals("any") || this.attacker_address.equals(session.peer1Addr))) {
                return false;
            }
        }
        //Lets check the host ports, if they don't match, return false.
        if(hostPeer == 1) {
            if(!hostPortMatches(session.peer1Port)) {
                return false;
            }
        }
        if(hostPeer == 2) {
            if(!hostPortMatches(session.peer2Port)) {
                return false;
            }
        }
        //Lets check the attacker ports. Same story.
        if(hostPeer == 2) {
            if(!attackerPortMatches(session.peer1Port)) {
                return false;
            }
        }
        if(hostPeer == 1) {
            if(!attackerPortMatches(session.peer2Port)) {
                return false;
            }
        }
        //Apply policy checks on payload contents
        boolean toMatch = false;
        boolean fromMatch = false;
        if(hostPeer == 1) {
            try {
                toMatch = contentMatch(session.fullPayloadToPeer1(), this.to_host);
                fromMatch = contentMatch(session.fullPayloadToPeer2(), this.from_host);
            } catch (Exception e) {
                System.err.println("Failed to parse TCP session");
                return false;
            }
        }
        if(hostPeer == 2) {
            try {
                toMatch = contentMatch(session.fullPayloadToPeer2(), this.to_host);
                fromMatch = contentMatch(session.fullPayloadToPeer1(), this.from_host);
            } catch (Exception e) {
                System.err.println("Failed to parse TCP session");
                return false;
            }
        }
        //Evaluate matches
        return toMatch || fromMatch;
    }
}
