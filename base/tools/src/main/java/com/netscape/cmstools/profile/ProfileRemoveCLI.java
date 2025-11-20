package com.netscape.cmstools.profile;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class ProfileRemoveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileRemoveCLI.class);

    public ProfileCLI profileCLI;

    public ProfileRemoveCLI(ProfileCLI profileCLI) {
        super("del", "Remove profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileId = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileCLI.caCLI.getSubsystemClient(client);
        ProfileClient profileClient = new ProfileClient(subsystemClient);
        profileClient.deleteProfile(profileId);

        MainCLI.printMessage("Deleted profile \"" + profileId + "\"");
    }

}
