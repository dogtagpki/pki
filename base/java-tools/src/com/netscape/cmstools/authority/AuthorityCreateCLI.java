package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.cmstools.cli.CLI;

public class AuthorityCreateCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityCreateCLI(AuthorityCLI authorityCLI) {
        super("create", "Create CAs", authorityCLI);
        this.authorityCLI = authorityCLI;

        Option optParent = new Option(null, "parent", true, "ID of parent CA");
        optParent.setArgName("id");
        options.addOption(optParent);

        Option optDesc = new Option(null, "desc", true, "Optional description");
        optDesc.setArgName("string");
        options.addOption(optDesc);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <dn>", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();
        if (cmdArgs.length != 1) {
            if (cmdArgs.length < 1)
                System.err.println("No DN specified.");
            else
                System.err.println("Too many arguments.");
            printHelp();
            System.exit(-1);
        }

        String parentAIDString = null;
        if (cmd.hasOption("parent")) {
            parentAIDString = cmd.getOptionValue("parent");
            try {
                new AuthorityID(parentAIDString);
            } catch (IllegalArgumentException e) {
                System.err.println("Bad CA ID: " + parentAIDString);
                printHelp();
                System.exit(-1);
            }
        } else {
            System.err.println("Must specify parent authority");
            printHelp();
            System.exit(-1);
        }

        String desc = null;
        if (cmd.hasOption("desc"))
            desc = cmd.getOptionValue("desc");

        String dn = cmdArgs[0];
        AuthorityData data = new AuthorityData(
            null, dn, null, parentAIDString, true /* enabled */, desc);
        AuthorityData newData = authorityCLI.authorityClient.createCA(data);
        AuthorityCLI.printAuthorityData(newData);
    }

}
