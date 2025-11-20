package com.netscape.cmstools.authority;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class AuthorityDisableCLI extends SubsystemCommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityDisableCLI(AuthorityCLI authorityCLI) {
        super("disable", "Disable CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No ID specified.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthorityData data = new AuthorityData(
            null, null, cmdArgs[0], null, null, null, false, null, null);

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = authorityCLI.caCLI.getSubsystemClient(client);
        AuthorityClient authorityClient = new AuthorityClient(subsystemClient);
        data = authorityClient.modifyCA(data);
        AuthorityCLI.printAuthorityData(data);
    }
}
