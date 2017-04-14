package csci476.lab5.IDS;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * Created by cetho on 4/14/2017.
 */
public class PacketHandler implements PcapPacketHandler<String> {

    private CaptureData captureData;
    private Policy policy;

    public PacketHandler(CaptureData captureData, Policy policy) {
        this.captureData = captureData;
        this.policy = policy;
    }

    public void nextPacket(PcapPacket pcapPacket, String ignored) {

    }
}
