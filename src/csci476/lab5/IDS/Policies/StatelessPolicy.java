package csci476.lab5.IDS.Policies;

import csci476.lab5.IDS.Policy;
import org.jnetpcap.packet.PcapPacket;

/**
 * Created by cetho on 4/14/2017.
 */
public class StatelessPolicy extends Policy {

    public boolean packetMatchesPolicy(PcapPacket packet) {
        return false;
    }

}