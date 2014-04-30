package com.netscape.cmstools.cert;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestReviewCLI extends CLI {

    CertCLI certCLI;
    List<String> actions = Arrays.asList(
        "approve", "reject", "cancel", "update", "validate", "assign", "unassign"
    );

    public CertRequestReviewCLI(CertCLI certCLI) {
        super("request-review", "Review certificate request", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "action", true, "Action: " + StringUtils.join(actions, ", "));
        option.setArgName("action");
        options.addOption(option);

        option = new Option(null, "file", true,
                            "File to store the retrieved certificate request.\n"
                          + "Action will be prompted for to run against request read in from file.");
        option.setArgName("filename");
        options.addOption(option);
    }

    @Override
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
            System.err.println("Error: Missing Certificate Request ID.");
            printHelp();
            System.exit(-1);
        }

        RequestId requestId = null;
        try {
            requestId = new RequestId(cmdArgs[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid certificate request ID " + cmdArgs[0] + ".");
            System.exit(-1);
        }

        // Since "--action <action>" and "--file <filename>" are mutually
        // exclusive, check to make certain that only one has been set
        if (cmd.hasOption("action") && cmd.hasOption("file")) {
            System.err.println("Error: The '--action <action>' and '--file <filename>' " +
                               "options are mutually exclusive!");
            printHelp();
            System.exit(-1);
        }

        String action = cmd.getOptionValue("action");
        String filename = null;

        if (action == null) {
            if (cmd.hasOption("file")) {
                filename = cmd.getOptionValue("file");
            } else {
                System.err.println("Error: Missing '--action <action>' or '--file <filename>' option.");
                printHelp();
                System.exit(-1);
            }

            if (filename == null || filename.trim().length() == 0) {
                System.err.println("Error: Missing output file name.");
                printHelp();
                System.exit(-1);
            }
        }

        // Retrieve certificate request.
        CertReviewResponse reviewInfo = null;
        try {
            reviewInfo = certCLI.certClient.reviewRequest(requestId);
        } catch (PKIException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }

        if (action == null) {
            // Store certificate request in a file.
            JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            FileOutputStream stream = new FileOutputStream(filename);
            marshaller.marshal(reviewInfo, stream);

            MainCLI.printMessage("Retrieved certificate request " + requestId);
            CertCLI.printCertReviewResponse(reviewInfo);
            System.out.println("  Filename: " + filename);
            if (verbose) System.out.println("  Nonce: " + reviewInfo.getNonce());
            System.out.println();

            while (true) {
                // Prompt for action.
                System.out.print("Action (" + StringUtils.join(actions, "/") + "): ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                action = reader.readLine().trim().toLowerCase();

                if (actions.contains(action)) break;
            }

            // Read certificate request file.
            Unmarshaller unmarshaller = context.createUnmarshaller();
            FileInputStream fis = new FileInputStream(filename);
            reviewInfo = (CertReviewResponse) unmarshaller.unmarshal(fis);
        }

        if (action.equalsIgnoreCase("approve")) {
            certCLI.certClient.approveRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Approved certificate request " + requestId);

        } else if (action.equalsIgnoreCase("reject")) {
            certCLI.certClient.rejectRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Rejected certificate request " + requestId);

        } else if (action.equalsIgnoreCase("cancel")) {
            certCLI.certClient.cancelRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Canceled certificate request " + requestId);

        } else if (action.equalsIgnoreCase("update")) {
            certCLI.certClient.updateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Updated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("validate")) {
            certCLI.certClient.validateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Validated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("assign")) {
            certCLI.certClient.assignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Assigned certificate request " + requestId);

        } else if (action.equalsIgnoreCase("unassign")) {
            certCLI.certClient.unassignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Unassigned certificate request " + requestId);

        } else {
            throw new Error("Invalid action: " + action);
        }
    }
}
