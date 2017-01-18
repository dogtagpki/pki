package com.netscape.cmstools.authority;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityRemoveCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityRemoveCLI(AuthorityCLI authorityCLI) {
        super("del", "Delete Authority", authorityCLI);
        this.authorityCLI = authorityCLI;

        options.addOption(null, "force", false, "Force delete");
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <dn>", options);
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
        authorityCLI.authorityClient.deleteCA(aidString);
        MainCLI.printMessage("Deleted authority \"" + aidString + "\"");
    }

}
