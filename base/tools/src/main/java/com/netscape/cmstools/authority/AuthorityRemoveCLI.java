package com.netscape.cmstools.authority;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class AuthorityRemoveCLI extends SubsystemCommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityRemoveCLI(AuthorityCLI authorityCLI) {
        super("del", "Delete Authority", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    @Override
    public void createOptions() {
        options.addOption(null, "force", false, "Force delete");
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

        } else if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments.");
        }

        if (!cmd.hasOption("force")) {
            System.out.print("Are you sure (Y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            if (!line.equalsIgnoreCase("Y")) {
                return;
            }
        }

        String aidString = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = authorityCLI.caCLI.getSubsystemClient(client);
        AuthorityClient authorityClient = new AuthorityClient(subsystemClient);
        authorityClient.deleteCA(aidString);

        MainCLI.printMessage("Deleted authority \"" + aidString + "\"");
    }
}
