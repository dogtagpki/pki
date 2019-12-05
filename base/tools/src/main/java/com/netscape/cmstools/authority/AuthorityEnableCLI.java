package com.netscape.cmstools.authority;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityEnableCLI extends CommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityEnableCLI(AuthorityCLI authorityCLI) {
        super("enable", "Enable CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No ID specified.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthorityData data = new AuthorityData(
            null, null, cmdArgs[0], null, null, null, true, null, null);

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        data = authorityClient.modifyCA(data);
        AuthorityCLI.printAuthorityData(data);
    }
}
