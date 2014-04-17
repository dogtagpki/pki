package com.netscape.cmstools.profile;

import java.util.Arrays;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileRemoveCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileRemoveCLI(ProfileCLI profileCLI) {
        super("del", "Remove profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID>", options);
    }

    public void execute(String[] args) throws Exception {

        // Check for "--help"
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        if (args.length != 1) {
            printHelp();
            System.exit(1);
        }

        String profileId = args[0];

        profileCLI.profileClient.deleteProfile(profileId);

        MainCLI.printMessage("Deleted profile \"" + profileId + "\"");
    }

}
