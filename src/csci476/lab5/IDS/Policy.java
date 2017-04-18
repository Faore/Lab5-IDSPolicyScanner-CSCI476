package csci476.lab5.IDS;

        import csci476.lab5.IDS.Policies.Protocol;
        import csci476.lab5.IDS.Policies.StatefulPolicy;
        import csci476.lab5.IDS.Policies.StatelessPolicy;
        import org.jnetpcap.packet.Payload;
        import org.jnetpcap.packet.PcapPacket;
        import org.jnetpcap.packet.format.FormatUtils;
        import org.jnetpcap.protocol.network.Ip4;

        import java.util.ArrayList;
        import java.util.regex.Matcher;
        import java.util.regex.Pattern;
        import java.lang.*;

/**
 * Created by cetho on 4/14/2017.
 */
public abstract class Policy {

    //Ports
    public int host_port = -1; //-1 = Any
    public int attacker_port = -1; //-1 Any;
    //Addresses
    public String attacker_address = null;
    public String host_address = null;
    //Packet Content Filters: Regex Expressions
    public ArrayList<Pattern> from_host = new ArrayList<Pattern>();
    public ArrayList<Pattern> to_host = new ArrayList<Pattern>();

    public boolean isStateful;

    public abstract boolean packetMatchesPolicy(PcapPacket packet);

    public static Policy policyFromFile(String policyContents) throws Exception {
        //Requirements
        boolean hostPresent = false;
        boolean protocolPresent = false;
        boolean hostPortPresent = false;
        boolean attackerPortPresent = false;
        boolean subpolicyPresent = false;
        boolean attackerPresent = false;
        //Create Policy
        Policy policy = createEmptyPolicy(policyContents);
        //Parse the file
        System.out.println("Creating policy with stateful: " + policy.isStateful);

        String[] policyLines = policyContents.split("\n");
        for (String line : policyLines) {
            //Consume empty lines
            if(line.trim().equals("")) {
                continue;
            }
            //Get the Host
            if(line.startsWith("host=")) {
                String ip = line.substring(5).trim();
                hostPresent = true;
                policy.host_address = ip;
                System.out.println("Host IP address: " + ip);
                continue;
            }
            //Protocol
            if(!policy.isStateful && line.startsWith("proto=")) {
                String protocol = line.substring(6).trim();
                if(protocol.trim().equals("tcp")) {
                    ((StatelessPolicy) policy).protocol = Protocol.TCP;
                } else if (protocol.contains("udp")) {
                    ((StatelessPolicy) policy).protocol = Protocol.UDP;
                } else if (protocol.contains("any")){
                    ((StatelessPolicy) policy).protocol = Protocol.Any;
                } else {
                    throw new Exception("Invalid protocol.");
                }
                protocolPresent = true;
                System.out.println("Protocol: " + ((StatelessPolicy) policy).protocol);
                continue;
            }
            //Host Port
            if(line.startsWith("host_port=")) {
                String rawPort = line.substring(10).trim();
                if(!rawPort.equals("any")) {
                    policy.host_port = Integer.parseInt(rawPort);
                } else {
                    policy.host_port = -1;
                }
                hostPortPresent = true;
                System.out.println("Host Port: " + policy.host_port);
                continue;
            }
            //Attacker Port
            if(line.startsWith("attacker_port=")) {
                String rawPort = line.substring(14).trim();
                if(!rawPort.equals("any")) {
                    policy.attacker_port = Integer.parseInt(rawPort);
                } else {
                    policy.attacker_port = -1;
                }
                attackerPortPresent = true;
                System.out.println("Attacker Port: " + policy.attacker_port);
                continue;
            }
            //Get the Attacker
            if(line.startsWith("attacker=")) {
                String ip = line.substring(9).trim();
                attackerPresent = true;
                policy.attacker_address = ip;
                System.out.println("Attacker IP address: " + ip);
                continue;
            }
            //To Host SubPolicy
            if(line.startsWith("to_host=")) {
                String regex = line.substring(8).trim();
                regex = regex.substring(1, regex.length() - 1);
                policy.to_host.add(Pattern.compile(regex));
                subpolicyPresent = true;
                System.out.println("Policy: To Host: " + regex);
                continue;
            }
            //From Host SubPolicy
            if(line.startsWith("from_host=")) {
                String regex = line.substring(10).trim();
                regex = regex.substring(1, regex.length() - 1);
                policy.from_host.add(Pattern.compile(regex));
                subpolicyPresent = true;
                System.out.println("Policy: From Host: " + regex);
                continue;
            }
        }

        if(!(hostPresent && ((protocolPresent && !policy.isStateful) || (!protocolPresent && policy.isStateful)) && hostPortPresent && attackerPortPresent && subpolicyPresent && attackerPresent)) {
            throw new Exception("Not all required configurations are in the policy file.");
        }

        return policy;
    }

    private static Policy createEmptyPolicy(String policyContents) throws Exception {
        //Find policy contents
        Policy policy = null;
        String[] lines = policyContents.split("\n");
        for (String line : lines) {
            if(line.contains("type=stateful")) {
                policy = new StatefulPolicy();
                break;
            }
            else if(line.contains("type=stateless")) {
                policy = new StatelessPolicy();
                break;
            }
        }
        if(policy == null) {
            throw new Exception("Policy type not included.");
        }
        return policy;
    }

    protected static boolean payloadMatch(Payload payload, ArrayList<Pattern> policies) {
        try {
            String data = new String(payload.data(), "UTF-8");
            return contentMatch(data, policies);
        } catch (Exception e) {
            System.err.println("Failed to parse packet payload.");
            return false;
        }
    }

    protected static boolean contentMatch(String content, ArrayList<Pattern> policies) {
        for ( Pattern pattern : policies ) {
            Matcher matcher = pattern.matcher(content);
            if(matcher.find()) {
                return true;
            }
        }
        return false;
    }

    protected boolean packetIsToHost(Ip4 ip4) {
        return FormatUtils.ip(ip4.destination()).equals(this.host_address);
    }

    protected boolean packetIsFromHost(Ip4 ip4) {
        return FormatUtils.ip(ip4.source()).equals(this.host_address);
    }

    protected boolean packetMatchesAttacker(byte[] ip) {
        return (this.attacker_address.equals("any") || FormatUtils.ip(ip).equals(this.attacker_address));
    }

    protected boolean hostPortMatches(int port) {
        if(this.host_port == -1 || this.host_port == port) {
            //Different Ports. No match.
            return true;
        } else {
            return false;
        }
    }

    protected boolean attackerPortMatches(int port) {
        if(this.attacker_port == -1 || this.attacker_port == port) {
            //Different Ports. No match.
            return true;
        } else {
            return false;
        }
    }
}