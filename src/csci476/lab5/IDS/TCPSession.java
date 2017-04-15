package csci476.lab5.IDS;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;

/**
 * Created by cetho on 4/15/2017.
 */
public class TCPSession {
    int sessionId;
    //We can associate connections with IP and port
    String peer1Addr;
    int peer1Port;

    String peer2Addr;
    int peer2Port;

    ArrayList<PcapPacket> packets;

    public TCPSession(PcapPacket packet, int sessionId) {

        this.sessionId = sessionId;

        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        packet.getHeader(ip4);
        packet.getHeader(tcp);

        peer1Port = tcp.source();
        peer2Port = tcp.destination();

        peer1Addr = FormatUtils.ip(ip4.source());
        peer2Addr = FormatUtils.ip(ip4.destination());

        packets = new ArrayList<PcapPacket>();
        packets.add(packet);
    }

    public boolean addPacketToSession(PcapPacket packet) {
        if(packetMatchesSession(packet)) {
            packets.add(packet);
            return true;
        }
        return false;
    }

    public boolean packetMatchesSession(PcapPacket packet) {
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        packet.getHeader(ip4);
        packet.getHeader(tcp);

        boolean peer1match = false;
        boolean peer2match = false;

        //Look For Peer 1
        if(peer1Addr.equals(FormatUtils.ip(ip4.source())) && tcp.source() == peer1Port) {
            peer1match = true;
        }
        if(peer1Addr.equals(FormatUtils.ip(ip4.destination())) && tcp.source() == peer1Port) {
            peer1match = true;
        }
        //Look For Peer 2
        if(peer2Addr.equals(FormatUtils.ip(ip4.source())) && tcp.source() == peer2Port) {
            peer1match = true;
        }
        if(peer2Addr.equals(FormatUtils.ip(ip4.destination())) && tcp.source() == peer2Port) {
            peer1match = true;
        }
        return peer1match && peer2match;
    }
}
