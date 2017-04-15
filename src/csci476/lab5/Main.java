package csci476.lab5;

import csci476.lab5.IDS.IDS;
import csci476.lab5.IDS.Policy;
import org.jnetpcap.Pcap;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) throws Exception {
        //Get the files we're going to be working on.
        String policyFile = null;
        String pcapFile = null;
        try {
            policyFile = args[0];
            pcapFile = args[1];
        } catch (Exception e) {}
        //Throw errors if we don't have all the files.
        if(policyFile == null) {
            throw new Exception("No policy file specified.");
        }
        if(pcapFile == null) {
            throw new Exception("No policy file specified.");
        }
        //Attempt to open the Policy file.
        String policyContents = null;
        try {
            policyContents = new String(Files.readAllBytes(Paths.get(policyFile)));
        } catch(Exception e) {
            System.out.println("Failed to open policy file.");
            throw e;
        }
        Policy policy = Policy.policyFromFile(policyContents);

        //Attempt to open the PcapFile using JNetWinPcap:
        final StringBuilder errorBuffer = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFile, errorBuffer);

        //If we couldn't open the file, lets tell the user why
        if (pcap == null) {
            System.err.printf("Failed to open the Pcap file:\n"
                    + errorBuffer.toString());
            return;
        }
        //We're good to go! Lets "boot" the IDS!
        IDS ids = new IDS(policy, pcap);
        ids.begin();
    }
}