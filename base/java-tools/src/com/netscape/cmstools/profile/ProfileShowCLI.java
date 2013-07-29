package com.netscape.cmstools.profile;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileShowCLI extends CLI {

    public ProfileCLI parent;

    public ProfileShowCLI(ProfileCLI parent) {
        super("show", "Show profiles");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <profile_id>", options);
    }

    public void execute(String[] args) throws Exception {
        CommandLine cmd = null;

        Option option = new Option(null, "output", true, "Output filename");
        option.setArgName("filename");
        options.addOption(option);

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cLineArgs = cmd.getArgs();
        if (cLineArgs.length < 1) {
            System.err.println("Error: Missing profile ID.");
            printHelp();
            System.exit(-1);
        }

        String profileId = cLineArgs[0];

        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");

            if (filename == null || filename.trim().length() == 0) {
                System.err.println("Error: Missing output file name.");
                printHelp();
                System.exit(-1);
            }
        }

        ProfileData profileData = parent.client.retrieveProfile(profileId);

        MainCLI.printMessage("Profile \"" + profileId + "\"");

        if (filename != null) {
            ProfileCLI.saveProfileToFile(filename, profileData);
        } else {
            ProfileCLI.printProfile(profileData, parent.parent.config.getServerURI());
        }
    }

}
