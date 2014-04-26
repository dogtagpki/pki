package com.netscape.cmstools.cert;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CertRequestProfileShowCLI extends CLI {

    public CertCLI certCLI;

    public CertRequestProfileShowCLI(CertCLI certCLI) {
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
            System.err.println("Error: Missing Profile ID.");
            printHelp();
            System.exit(-1);
        }

        String profileId = cmdArgs[0];

        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");

            if (filename == null || filename.trim().length() == 0) {
                System.err.println("Error: Missing output file name.");
                printHelp();
                System.exit(-1);
            }
        }

        CertEnrollmentRequest request = certCLI.certClient.getEnrollmentTemplate(profileId);

        MainCLI.printMessage("Enrollment Template for Profile \"" + profileId + "\"");

        if (filename != null) {
            ProfileCLI.saveEnrollmentTemplateToFile(filename, request);
        } else {
            ProfileCLI.printEnrollmentTemplate(request);
        }
    }
}
