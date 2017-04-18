package csci476.lab5.IDS;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

/**
 * Created by cetho on 4/15/2017.
 */
public class TCPSession {
    public int sessionId;
    //We can associate connections with IP and port
    public String peer1Addr;
    public int peer1Port;

    public String peer2Addr;
    public int peer2Port;

    ArrayList<PcapPacket> packetsToPeer1;
    ArrayList<PcapPacket> packetsToPeer2;

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

        packetsToPeer1 = new ArrayList<PcapPacket>();
        packetsToPeer2 = new ArrayList<PcapPacket>();
        packetsToPeer2.add(packet);
    }

    public boolean addPacketToSession(PcapPacket packet) {
        if(packetMatchesSession(packet)) {
            Ip4 ip4 = new Ip4();
            packet.getHeader(ip4);
            if(FormatUtils.ip(ip4.destination()).equals(peer1Addr)) {
                packetsToPeer1.add(packet);
            } else {
                packetsToPeer2.add(packet);
            }
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

    public String fullPayloadToPeer1() throws UnsupportedEncodingException {
        //Instead of the contents of the payload, use the entire packet.
        String fullContents = "";
        for(PcapPacket packet : packetsToPeer1) {
            fullContents = fullContents + new String(packet.getByteArray(0, packet.size()), "UTF-8");
        }
        return fullContents;
    }

    public String fullPayloadToPeer2() throws UnsupportedEncodingException {
        String fullContents = "";
        for(PcapPacket packet : packetsToPeer2) {
            fullContents = fullContents + new String(packet.getByteArray(0, packet.size()), "UTF-8");
        }
        return fullContents;
    }
}
