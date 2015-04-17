package com.netscape.cmstools.profile;

import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

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
            System.err.println("Error: No filename specified.");
            printHelp();
            System.exit(-1);
        }

        String filename = cmdArgs[0];
        if (filename == null || filename.trim().length() == 0) {
            System.err.println("Error: Missing input file name.");
            printHelp();
            System.exit(-1);
        }

        if (cmd.hasOption("raw")) {
            Properties properties = ProfileCLI.readRawProfileFromFile(filename);
            String profileId = properties.getProperty("profileId");
            profileCLI.profileClient.createProfileRaw(properties).store(System.out, null);
            MainCLI.printMessage("Added profile " + profileId);
        } else {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileCLI.profileClient.createProfile(data);

            MainCLI.printMessage("Added profile " + data.getId());

            ProfileCLI.printProfile(data, profileCLI.getClient().getConfig().getServerURI());
        }
    }
}
