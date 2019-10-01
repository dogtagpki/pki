package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CACertRequestProfileShowCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestProfileShowCLI.class);

    public CACertCLI certCLI;

    public CACertRequestProfileShowCLI(CACertCLI certCLI) {
        super("request-profile-show", "Get Enrollment template", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "Output filename");
        option.setArgName("filename");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.Level.INFO);
        }

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

        CACertClient certClient = certCLI.getCertClient();
        CertEnrollmentRequest request = certClient.getEnrollmentTemplate(profileId);

        MainCLI.printMessage("Enrollment Template for Profile \"" + profileId + "\"");

        if (filename != null) {
            ProfileCLI.saveEnrollmentTemplateToFile(filename, request);
        } else {
            ProfileCLI.printEnrollmentTemplate(request);
        }
    }
}
