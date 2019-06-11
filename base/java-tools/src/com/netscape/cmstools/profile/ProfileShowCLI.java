package com.netscape.cmstools.profile;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileShowCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileShowCLI(ProfileCLI profileCLI) {
        super("show", "Show profiles", profileCLI);
        this.profileCLI = profileCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option optFilename = new Option(null, "output", true, "Output filename");
        optFilename.setArgName("filename");
        options.addOption(optFilename);

        Option optRaw = new Option(null, "raw", false, "Use raw format");
        optRaw.setArgName("raw");
        options.addOption(optRaw);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

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

        ProfileClient profileClient = profileCLI.getProfileClient();

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
                ProfileCLI.printProfile(profileData, profileCLI.getConfig().getServerURL().toURI());
            }
        }
    }

}
