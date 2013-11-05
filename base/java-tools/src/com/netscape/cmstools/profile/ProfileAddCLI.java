package com.netscape.cmstools.profile;

import java.io.FileNotFoundException;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileAddCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileAddCLI(ProfileCLI profileCLI) {
        super("add", "Add profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <file>", options);
    }

    public void execute(String[] args) {
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cLineArgs = cmd.getArgs();

        if (cLineArgs.length < 1) {
            System.err.println("Error: No filename specified.");
            printHelp();
            System.exit(-1);
        }
        String filename = cLineArgs[0];
        if (filename == null || filename.trim().length() == 0) {
            System.err.println("Error: Missing input file name.");
            printHelp();
            System.exit(-1);
        }

        try {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileCLI.profileClient.createProfile(data);

            MainCLI.printMessage("Added profile " + data.getId());

            ProfileCLI.printProfile(data, profileCLI.getClient().getConfig().getServerURI());
        } catch (FileNotFoundException | JAXBException  e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        }
    }
}
