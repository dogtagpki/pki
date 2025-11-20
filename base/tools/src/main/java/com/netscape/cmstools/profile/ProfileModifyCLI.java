package com.netscape.cmstools.profile;

import java.io.ByteArrayInputStream;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class ProfileModifyCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileModifyCLI.class);

    public ProfileCLI profileCLI;

    public ProfileModifyCLI(ProfileCLI profileCLI) {
        super("mod", "Modify profiles", profileCLI);
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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileCLI.caCLI.getSubsystemClient(client);
        ProfileClient profileClient = new ProfileClient(subsystemClient);

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

            ProfileCLI.printProfile(data);
        }
    }
}
