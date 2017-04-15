package csci476.lab5.IDS;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * Created by cetho on 4/14/2017.
 */
public class PacketHandler implements PcapPacketHandler<String> {

    public int parsedPacketCount = 0;
    private CaptureData captureData;
    private Policy policy;

    public PacketHandler(CaptureData captureData, Policy policy) {
        this.captureData = captureData;
        this.policy = policy;
    }

    public void nextPacket(PcapPacket packet, String ignored) {
        if(packet.hasHeader(Tcp.ID)) {
            if(policy.isStateful) {
                parseTcpPacketWithSession(packet);
            } else {
                try {
                    parseTcpPacket(packet);
                } catch (Exception e) {
                    System.err.println("Failed to parse packet.");
                }

            }
        } else if(packet.hasHeader(Udp.ID)) {
            parseUdpPacket(packet);
        }
    }
    //Check if packet matches
    private void parseTcpPacket(PcapPacket packet) throws java.io.UnsupportedEncodingException {
        parsedPacketCount++;
        if(policy.packetMatchesPolicy(packet)) {
            Tcp tcp = new Tcp();
            Ip4 ip4 = new Ip4();
            Payload payload = new Payload();

            packet.getHeader(tcp);
            packet.getHeader(ip4);


            System.out.println("IDS:Stateless: Matched TCP Packet " + parsedPacketCount + ": ");
            System.out.println("\tFrom: " + FormatUtils.ip(ip4.source()));
            System.out.println("\tTo: " + FormatUtils.ip(ip4.destination()));
        }
    }

    //This method will track sessions in CaptureData
    private void parseTcpPacketWithSession(PcapPacket packet) {

    }

    private void parseUdpPacket(PcapPacket packet) {

    }
}
