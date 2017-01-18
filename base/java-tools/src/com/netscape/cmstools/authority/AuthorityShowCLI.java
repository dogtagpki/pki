package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

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
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        String caIDString = null;

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments.");

        } else if (cmdArgs.length == 1) {
            caIDString = cmdArgs[0];
        }

        if (cmd.hasOption("host-authority")) {
            if (caIDString != null) {
                throw new Exception("Authority ID and --host-authority are mutually exclusive.");
            }
            caIDString = AuthorityResource.HOST_AUTHORITY;
        }

        if (caIDString == null) {
            throw new Exception("No ID specified.");
        }

        AuthorityData data = authorityCLI.authorityClient.getCA(caIDString);
        AuthorityCLI.printAuthorityData(data);
    }

}
