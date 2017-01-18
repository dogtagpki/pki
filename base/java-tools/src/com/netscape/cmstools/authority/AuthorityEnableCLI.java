package com.netscape.cmstools.authority;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

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
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No ID specified.");
        }

        AuthorityData data = new AuthorityData(
            null, null, cmdArgs[0], null, null, null, true, null, null);
        data = authorityCLI.authorityClient.modifyCA(data);
        AuthorityCLI.printAuthorityData(data);
    }

}
