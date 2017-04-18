package csci476.lab5.IDS;

import csci476.lab5.IDS.Policies.StatefulPolicy;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;

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
        //Attempt to match TCP sessions.
        if(policy.isStateful) {
            for ( TCPSession session : captureData.sessions ) {
                if(((StatefulPolicy) policy).sessionMatchesPolicy(session) ) {
                    System.out.println("IDS:Stateful: Matched TCP Session " + session.sessionId + ":");
                    System.out.println("\tPeer 1: " + session.peer1Addr + ":" + session.peer1Port);
                    System.out.println("\tPeer 2: " + session.peer2Addr + ":" + session.peer2Port);
                }
            }
        }

        System.out.println("\n---------------------------------------------\n\n" +
                "Complete: Parsed " + packetHandler.parsedPacketCount + " packets.");
    }
}
