package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

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
        Tcp tcp = new Tcp();
        Ip4 ip4 = new Ip4();
        Payload payload = new Payload();

        packet.getHeader(tcp);
        packet.getHeader(ip4);

        //Check if packet it to the host
        if(packetIsToHost(ip4)) {
            if(packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                payloadMatch(payload, this.to_host);
            }
        } else if (packetIsFromHost(ip4)) {
            if(packet.hasHeader(Payload.ID)) {
                packet.getHeader(payload);
                payloadMatch(payload, this.from_host);
            }
        }
        return false;
    }
}