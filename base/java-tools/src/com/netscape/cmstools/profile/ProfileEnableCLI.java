package com.netscape.cmstools.profile;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileEnableCLI extends CLI {

    public ProfileCLI parent;

    public ProfileEnableCLI(ProfileCLI parent) {
        super("enable", "Enable profiles");
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

        parent.client.enableProfile(profileId);

        MainCLI.printMessage("Enabled profile \"" + profileId + "\"");
    }

}
