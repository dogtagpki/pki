package com.netscape.cmstools.profile;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileDisableCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileDisableCLI(ProfileCLI profileCLI) {
        super("disable", "Disable profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
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

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: No Profile ID specified.");
            printHelp();
            System.exit(-1);
        }

        String profileId = args[0];

        profileCLI.profileClient.disableProfile(profileId);

        MainCLI.printMessage("Disabled profile \"" + profileId + "\"");
    }


}
