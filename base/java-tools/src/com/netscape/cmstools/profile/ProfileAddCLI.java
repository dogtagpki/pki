package com.netscape.cmstools.profile;

import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileAddCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileAddCLI(ProfileCLI profileCLI) {
        super("add", "Add profiles", profileCLI);
        this.profileCLI = profileCLI;

        Option optRaw = new Option(null, "raw", false, "Use raw format");
        optRaw.setArgName("raw");
        options.addOption(optRaw);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <file> [OPTIONS...]", options);
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
            throw new Exception("No filename specified.");
        }

        String filename = cmdArgs[0];
        if (filename == null || filename.trim().length() == 0) {
            throw new Exception("Missing input file name.");
        }

        ProfileClient profileClient = profileCLI.getProfileClient();

        if (cmd.hasOption("raw")) {
            Properties properties = ProfileCLI.readRawProfileFromFile(filename);
            String profileId = properties.getProperty("profileId");
            profileClient.createProfileRaw(properties).store(System.out, null);
            MainCLI.printMessage("Added profile " + profileId);
        } else {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileClient.createProfile(data);

            MainCLI.printMessage("Added profile " + data.getId());

            ProfileCLI.printProfile(data, profileCLI.getConfig().getServerURI());
        }
    }
}
