package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.authority.AuthorityClient;
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
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No DN specified.");

        } else if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments.");
        }

        String parentAIDString = null;
        if (cmd.hasOption("parent")) {
            parentAIDString = cmd.getOptionValue("parent");
            try {
                new AuthorityID(parentAIDString);
            } catch (IllegalArgumentException e) {
                throw new Exception("Bad CA ID: " + parentAIDString, e);
            }
        } else {
            throw new Exception("Must specify parent authority");
        }

        String desc = null;
        if (cmd.hasOption("desc"))
            desc = cmd.getOptionValue("desc");

        String dn = cmdArgs[0];
        AuthorityData data = new AuthorityData(
            null, dn, null, parentAIDString, null, null, true /* enabled */, desc, null);
        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        AuthorityData newData = authorityClient.createCA(data);
        AuthorityCLI.printAuthorityData(newData);
    }

}
