package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.cmstools.cli.CLI;

public class AuthorityEnableCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityEnableCLI(AuthorityCLI authorityCLI) {
        super("enable", "Enable CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
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

        if (cmdArgs.length < 1) {
            System.err.println("Error: No ID specified.");
            printHelp();
            System.exit(-1);
        }

        AuthorityData data = new AuthorityData(
            null, null, cmdArgs[0], null, null, null, true, null, null);
        data = authorityCLI.authorityClient.modifyCA(data);
        AuthorityCLI.printAuthorityData(data);
    }

}
