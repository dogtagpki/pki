package com.netscape.cmstools.profile;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ProfileClient profileClient = profileCLI.getProfileClient();

        if (cmd.hasOption("raw")) {
            byte[] cfg = ProfileCLI.readRawProfileFromFile(filename);

            // read profileId from the configuration
            Properties p = new Properties();
            p.load(new ByteArrayInputStream(cfg));
            String profileId = p.getProperty("profileId");

            byte[] resp = profileClient.modifyProfileRaw(profileId, cfg);
            System.out.write(resp);
            MainCLI.printMessage("Modified profile " + profileId);
        } else {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileClient.modifyProfile(data);

            MainCLI.printMessage("Modified profile " + data.getId());

            ProfileCLI.printProfile(data, profileCLI.getConfig().getServerURL().toURI());
        }
    }
}
