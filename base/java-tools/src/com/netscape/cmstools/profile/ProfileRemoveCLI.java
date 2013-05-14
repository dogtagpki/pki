package com.netscape.cmstools.profile;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileRemoveCLI extends CLI {

    public ProfileCLI parent;

    public ProfileRemoveCLI(ProfileCLI parent) {
        super("del", "Remove profiles");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <profile_id>", options);
    }

    public void execute(String[] args) throws Exception {

        if (args.length != 1) {
            printHelp();
            System.exit(1);
        }

        String profileId = args[0];

        parent.client.deleteProfile(profileId);

        MainCLI.printMessage("Deleted profile \"" + profileId + "\"");
    }

}
