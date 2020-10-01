package com.netscape.cmstools.authority;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityRemoveCLI extends CommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityRemoveCLI(AuthorityCLI authorityCLI) {
        super("del", "Delete Authority", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force delete");
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

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

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        authorityClient.deleteCA(aidString);

        MainCLI.printMessage("Deleted authority \"" + aidString + "\"");
    }
}
