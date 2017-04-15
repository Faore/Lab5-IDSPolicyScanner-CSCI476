package csci476.lab5.IDS;

import org.jnetpcap.Pcap;

/**
 * Created by cetho on 4/14/2017.
 */
public class IDS {

    private Pcap pcap;
    private Policy policy;
    private CaptureData captureData;

    public IDS(Policy policy, Pcap pcap) {
        this.pcap = pcap;
        this.policy = policy;
    }

    public void begin() {

        System.out.println("\n---------------------------------------------\n\n" +
                "Beginning to monitor packets.");

        CaptureData captureData = new CaptureData();
        PacketHandler packetHandler = new PacketHandler(captureData, this.policy);

        try {
            //Arguments, Read all the packets, the packet handle, extra string you pass in with no useful information.
            pcap.loop(-1, packetHandler, "");
        } finally {
            pcap.close();
        }
        System.out.println("\n---------------------------------------------\n\n" +
                "Complete: Parsed " + packetHandler.parsedPacketCount + " packets.");
    }
}
