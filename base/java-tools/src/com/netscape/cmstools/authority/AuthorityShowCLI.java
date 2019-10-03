package com.netscape.cmstools.authority;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityShowCLI extends CommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityShowCLI(AuthorityCLI authorityCLI) {
        super("show", "Show CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    public void createOptions() {
        Option optParent = new Option(
            null, "host-authority", false, "Show host authority");
        options.addOption(optParent);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments.");

        }

        String caIDString = null;

        if (cmdArgs.length == 1) {
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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        AuthorityData data = authorityClient.getCA(caIDString);
        AuthorityCLI.printAuthorityData(data);
    }
}
