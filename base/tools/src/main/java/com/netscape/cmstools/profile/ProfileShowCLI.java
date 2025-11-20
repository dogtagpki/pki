package com.netscape.cmstools.profile;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class ProfileShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileShowCLI.class);

    public ProfileCLI profileCLI;

    public ProfileShowCLI(ProfileCLI profileCLI) {
        super("show", "Show profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option optFilename = new Option(null, "output", true, "Output filename");
        optFilename.setArgName("filename");
        options.addOption(optFilename);

        Option optRaw = new Option(null, "raw", false, "Use raw format");
        optRaw.setArgName("raw");
        options.addOption(optRaw);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileId = cmdArgs[0];

        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");

            if (filename == null || filename.trim().length() == 0) {
                throw new Exception("Missing output file name.");
            }
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileCLI.caCLI.getSubsystemClient(client);
        ProfileClient profileClient = new ProfileClient(subsystemClient);

        if (cmd.hasOption("raw")) {
            byte[] cfg = profileClient.retrieveProfileRaw(profileId);

            if (filename != null) {
                Files.write(Paths.get(filename), cfg);
                MainCLI.printMessage("Saved profile " + profileId + " to " + filename);
            } else {
                System.out.write(cfg);
            }
        } else {
            MainCLI.printMessage("Profile \"" + profileId + "\"");
            ProfileData profileData = profileClient.retrieveProfile(profileId);

            if (filename != null) {
                ProfileCLI.saveProfileToFile(filename, profileData);
            } else {
                ProfileCLI.printProfile(profileData);
            }
        }
    }

}
