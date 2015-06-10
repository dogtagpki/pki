package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.cmstools.cli.CLI;

public class AuthorityShowCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityShowCLI(AuthorityCLI authorityCLI) {
        super("show", "Show CAs", authorityCLI);
        this.authorityCLI = authorityCLI;

        Option optParent = new Option(
            null, "host-authority", false, "Show host authority");
        options.addOption(optParent);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
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

        String caIDString = null;
        if (cmdArgs.length > 1) {
            System.err.println("Error: too many arguments.");
            printHelp();
            System.exit(-1);
        } else if (cmdArgs.length == 1) {
            caIDString = cmdArgs[0];
        }

        if (cmd.hasOption("host-authority")) {
            if (caIDString != null) {
                System.err.println("Error: authority ID and --host-authority are mutually exclusive.");
                printHelp();
                System.exit(-1);
            }
            caIDString = AuthorityResource.HOST_AUTHORITY;
        }

        if (caIDString == null) {
            System.err.println("Error: No ID specified.");
            printHelp();
            System.exit(-1);
        }

        AuthorityData data = authorityCLI.authorityClient.getCA(caIDString);
        AuthorityCLI.printAuthorityData(data);
    }

}
