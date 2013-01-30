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

    CertCLI parent;
    List<String> actions = Arrays.asList(
        "approve", "reject", "cancel", "update", "validate", "assign", "unassign"
    );

    public CertRequestReviewCLI(CertCLI parent) {
        super("request-review", "Review certificate request");
        this.parent = parent;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <Request ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(String[] args) throws Exception {
        CommandLine cmd = null;

        Option option = new Option(null, "action", true, "Action: " + StringUtils.join(actions, ", "));
        option.setArgName("action");
        options.addOption(option);

        option = new Option(null, "output", true, "Output filename");
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
            System.err.println("Error: Missing certificate request ID.");
            printHelp();
            System.exit(-1);
        }

        RequestId requestId = null;
        try {
            requestId = new RequestId(cLineArgs[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid certificate request ID " + cLineArgs[0] + ".");
            System.exit(-1);
        }

        String action = cmd.getOptionValue("action");
        String filename = null;

        if (action == null) {
            if (cmd.hasOption("output")) {
                filename = cmd.getOptionValue("output");
            } else {
                System.err.println("Error: Missing output file name.");
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
            reviewInfo = parent.client.reviewRequest(requestId);
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
            parent.client.approveRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Approved certificate request " + requestId);

        } else if (action.equalsIgnoreCase("reject")) {
            parent.client.rejectRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Rejected certificate request " + requestId);

        } else if (action.equalsIgnoreCase("cancel")) {
            parent.client.cancelRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Canceled certificate request " + requestId);

        } else if (action.equalsIgnoreCase("update")) {
            parent.client.updateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Updated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("validate")) {
            parent.client.validateRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Validated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("assign")) {
            parent.client.assignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Assigned certificate request " + requestId);

        } else if (action.equalsIgnoreCase("unassign")) {
            parent.client.unassignRequest(reviewInfo.getRequestId(), reviewInfo);
            MainCLI.printMessage("Unassigned certificate request " + requestId);

        } else {
            throw new Error("Invalid action: " + action);
        }
    }
}
