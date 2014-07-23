package com.netscape.cmstools.profile;

import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
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
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            System.err.println("Error: No Profile ID specified.");
            printHelp();
            System.exit(-1);
        }

        String profileId = cmdArgs[0];

        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");

            if (filename == null || filename.trim().length() == 0) {
                System.err.println("Error: Missing output file name.");
                printHelp();
                System.exit(-1);
            }
        }

        if (cmd.hasOption("raw")) {
            Properties profileConfig = profileCLI.profileClient.retrieveProfileRaw(profileId);

            if (filename != null) {
                profileConfig.store(new FileOutputStream(filename), null);
                MainCLI.printMessage("Saved profile " + profileId + " to " + filename);
            } else {
                profileConfig.store(System.out, null);
            }
        } else {
            MainCLI.printMessage("Profile \"" + profileId + "\"");
            ProfileData profileData = profileCLI.profileClient.retrieveProfile(profileId);

            if (filename != null) {
                ProfileCLI.saveProfileToFile(filename, profileData);
            } else {
                ProfileCLI.printProfile(profileData, profileCLI.getClient().getConfig().getServerURI());
            }
        }
    }

}
