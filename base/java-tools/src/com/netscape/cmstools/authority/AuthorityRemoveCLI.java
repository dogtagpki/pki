package com.netscape.cmstools.authority;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

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
        if (cmdArgs.length != 1) {
            if (cmdArgs.length < 1)
                System.err.println("No ID specified.");
            else
                System.err.println("Too many arguments.");
            printHelp();
            System.exit(-1);
        }

        if (!cmd.hasOption("force")) {
            System.out.print("Are you sure (Y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            if (!line.equalsIgnoreCase("Y")) {
                System.exit(-1);
            }
        }

        String aidString = cmdArgs[0];
        authorityCLI.authorityClient.deleteCA(aidString);
        MainCLI.printMessage("Deleted authority \"" + aidString + "\"");
    }

}
