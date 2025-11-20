package com.netscape.cmstools.authority;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class AuthorityShowCLI extends SubsystemCommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityShowCLI(AuthorityCLI authorityCLI) {
        super("show", "Show CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    @Override
    public void createOptions() {
        Option optParent = new Option(
            null, "host-authority", false, "Show host authority");
        options.addOption(optParent);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

    @Override
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

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = authorityCLI.caCLI.getSubsystemClient(client);
        AuthorityClient authorityClient = new AuthorityClient(subsystemClient);
        AuthorityData data = authorityClient.getCA(caIDString);
        AuthorityCLI.printAuthorityData(data);
    }
}
