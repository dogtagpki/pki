package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CACertRequestProfileShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestProfileShowCLI.class);

    public CACertRequestCLI certRequestCLI;

    public CACertRequestProfileShowCLI(CACertRequestCLI certRequestCLI) {
        super("profile-show", "Get Enrollment template", certRequestCLI);
        this.certRequestCLI = certRequestCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "Output filename");
        option.setArgName("filename");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing Profile ID.");
        }

        String profileId = cmdArgs[0];

        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");

            if (filename == null || filename.trim().length() == 0) {
                throw new Exception("Missing output file name.");
            }
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CACertClient certClient = certRequestCLI.getCertClient(client);
        CertEnrollmentRequest request = certClient.getEnrollmentTemplate(profileId);

        MainCLI.printMessage("Enrollment Template for Profile \"" + profileId + "\"");

        if (filename != null) {
            ProfileCLI.saveEnrollmentTemplateToFile(filename, request);
        } else {
            ProfileCLI.printEnrollmentTemplate(request);
        }
    }
}
