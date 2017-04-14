package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import org.jnetpcap.packet.PcapPacket;

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
        return false;
    }

}