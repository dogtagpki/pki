package com.netscape.cmstools.profile;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class ProfileAddCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileAddCLI.class);

    public ProfileCLI profileCLI;

    public ProfileAddCLI(ProfileCLI profileCLI) {
        super("add", "Add profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    @Override
    public void createOptions() {
        Option optRaw = new Option(null, "raw", false, "Use raw format");
        optRaw.setArgName("raw");
        options.addOption(optRaw);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <file> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No filename specified.");
        }

        String filename = cmdArgs[0];
        if (filename == null || filename.trim().length() == 0) {
            throw new Exception("Missing input file name.");
        }

        if (!Files.exists(Path.of(filename))) {
            throw new CLIException("File not found: " + filename);
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileCLI.caCLI.getSubsystemClient(client);
        ProfileClient profileClient = new ProfileClient(subsystemClient);

        if (cmd.hasOption("raw")) {
            byte[] properties = ProfileCLI.readRawProfileFromFile(filename);

            // read profileId from the configuration
            Properties p = new Properties();
            p.load(new ByteArrayInputStream(properties));
            String profileId = p.getProperty("profileId");

            byte[] resp = profileClient.createProfileRaw(properties);
            System.out.write(resp);
            MainCLI.printMessage("Added profile " + profileId);
        } else {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileClient.createProfile(data);

            MainCLI.printMessage("Added profile " + data.getId());

            ProfileCLI.printProfile(data);
        }
    }
}
