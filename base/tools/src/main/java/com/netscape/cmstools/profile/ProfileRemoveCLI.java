package com.netscape.cmstools.profile;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileRemoveCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileRemoveCLI.class);

    public ProfileCLI profileCLI;

    public ProfileRemoveCLI(ProfileCLI profileCLI) {
        super("del", "Remove profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileId = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ProfileClient profileClient = profileCLI.getProfileClient();
        profileClient.deleteProfile(profileId);

        MainCLI.printMessage("Deleted profile \"" + profileId + "\"");
    }

}
