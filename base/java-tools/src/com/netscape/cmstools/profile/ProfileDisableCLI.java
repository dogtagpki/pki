package com.netscape.cmstools.profile;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileDisableCLI extends CLI {

    public ProfileCLI parent;

    public ProfileDisableCLI(ProfileCLI parent) {
        super("disable", "Disable profiles");
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

        parent.client.disableProfile(profileId);

        MainCLI.printMessage("Disabled profile \"" + profileId + "\"");
    }


}
