package csci476.lab5.IDS;

import csci476.lab5.IDS.Policies.StatefulPolicy;
import csci476.lab5.IDS.Policies.StatelessPolicy;
import org.jnetpcap.packet.PcapPacket;

/**
 * Created by cetho on 4/14/2017.
 */
public abstract class Policy {

    public boolean isStateful;

    public abstract boolean packetMatchesPolicy(PcapPacket packet);

    public static Policy policyFromFile(String policyContents) {
        return new StatefulPolicy();
    }
}