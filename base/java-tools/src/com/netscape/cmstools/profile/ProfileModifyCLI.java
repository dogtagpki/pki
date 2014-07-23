package com.netscape.cmstools.profile;

import java.io.IOException;
import java.util.Arrays;
import java.util.Properties;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileModifyCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileModifyCLI(ProfileCLI profileCLI) {
        super("mod", "Modify profiles", profileCLI);
        this.profileCLI = profileCLI;

        Option optRaw = new Option(null, "raw", false, "Use raw format");
        optRaw.setArgName("raw");
        options.addOption(optRaw);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <file> [OPTIONS...]", options);
    }

    public void execute(String[] args) {
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

        try {
            if (cmd.hasOption("raw")) {
                Properties properties = ProfileCLI.readRawProfileFromFile(filename);
                String profileId = properties.getProperty("profileId");
                profileCLI.profileClient.modifyProfileRaw(profileId, properties).store(System.out, null);
                MainCLI.printMessage("Modified profile " + profileId);
            } else {
                ProfileData data = ProfileCLI.readProfileFromFile(filename);
                data = profileCLI.profileClient.modifyProfile(data);

                MainCLI.printMessage("Modified profile " + data.getId());

                ProfileCLI.printProfile(data, profileCLI.getClient().getConfig().getServerURI());
            }
        } catch (IOException | JAXBException  e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        }
    }
}
