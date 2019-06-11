package com.netscape.cmstools.ca;

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
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestReviewCLI extends CLI {

    CACertCLI certCLI;
    List<String> actions = Arrays.asList(
        "approve", "reject", "cancel", "update", "validate", "assign", "unassign"
    );

    public CACertRequestReviewCLI(CACertCLI certCLI) {
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
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing Certificate Request ID.");
        }

        RequestId requestId = null;
        try {
            requestId = new RequestId(cmdArgs[0]);
        } catch (NumberFormatException e) {
            throw new Exception("Invalid certificate request ID " + cmdArgs[0] + ".", e);
        }

        // Since "--action <action>" and "--file <filename>" are mutually
        // exclusive, check to make certain that only one has been set
        if (cmd.hasOption("action") && cmd.hasOption("file")) {
            throw new Exception("The '--action <action>' and '--file <filename>' " +
                                "options are mutually exclusive!");
        }

        String action = cmd.getOptionValue("action");
        String filename = null;

        if (action == null) {
            if (cmd.hasOption("file")) {
                filename = cmd.getOptionValue("file");
            } else {
                throw new Exception("Missing '--action <action>' or '--file <filename>' option.");
            }

            if (filename == null || filename.trim().length() == 0) {
                throw new Exception("Missing output file name.");
            }
        }

        // Retrieve certificate request.
        CACertClient certClient = certCLI.getCertClient();
        CertReviewResponse reviewInfo = certClient.reviewRequest(requestId);

        if (action == null) {
            // Store certificate request in a file.
            JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            FileOutputStream stream = new FileOutputStream(filename);
            marshaller.marshal(reviewInfo, stream);

            MainCLI.printMessage("Retrieved certificate request " + requestId);
            CACertCLI.printCertReviewResponse(reviewInfo);
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
            certClient.approveRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Approved certificate request " + requestId);

        } else if (action.equalsIgnoreCase("reject")) {
            certClient.rejectRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Rejected certificate request " + requestId);

        } else if (action.equalsIgnoreCase("cancel")) {
            certClient.cancelRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Canceled certificate request " + requestId);

        } else if (action.equalsIgnoreCase("update")) {
            certClient.updateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Updated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("validate")) {
            certClient.validateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Validated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("assign")) {
            certClient.assignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Assigned certificate request " + requestId);

        } else if (action.equalsIgnoreCase("unassign")) {
            certClient.unassignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Unassigned certificate request " + requestId);

        } else {
            throw new Exception("Invalid action: " + action);
        }

        CertRequestInfo certRequest = certClient.getRequest(requestId);
        CACertCLI.printCertRequestInfo(certRequest);
    }
}
