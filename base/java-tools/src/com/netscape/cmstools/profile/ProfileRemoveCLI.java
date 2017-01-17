package com.netscape.cmstools.profile;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileRemoveCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileRemoveCLI(ProfileCLI profileCLI) {
        super("del", "Remove profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileId = args[0];

        profileCLI.profileClient.deleteProfile(profileId);

        MainCLI.printMessage("Deleted profile \"" + profileId + "\"");
    }

}
