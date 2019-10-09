package com.netscape.cmstools.ca;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestReviewCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestReviewCLI.class);

    CACertRequestCLI certRequestCLI;

    List<String> actions = Arrays.asList(
        "approve", "reject", "cancel", "update", "validate", "assign", "unassign"
    );

    public CACertRequestReviewCLI(CACertRequestCLI certRequestCLI) {
        super("review", "Review certificate request", certRequestCLI);
        this.certRequestCLI = certRequestCLI;
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
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing certificate request ID");
        }

        RequestId requestId;
        try {
            requestId = new RequestId(cmdArgs[0]);
        } catch (NumberFormatException e) {
            throw new Exception("Invalid certificate request ID: " + cmdArgs[0], e);
        }

        String action = cmd.getOptionValue("action");
        String filename = cmd.getOptionValue("file");

        if (action != null && filename != null) {
            throw new Exception("Action and filename are mutually exclusive");
        }

        if (action == null && filename == null) {
            throw new Exception("Missing action or filename");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        logger.info("Retrieving certificate request " + requestId);
        CACertClient certClient = certRequestCLI.getCertClient();
        CertReviewResponse reviewInfo = certClient.reviewRequest(requestId);
        logger.info("Nonce: " + reviewInfo.getNonce());

        if (filename != null) {

            MainCLI.printMessage("Retrieved certificate request " + requestId);
            CACertRequestCLI.printCertReviewResponse(reviewInfo);

            logger.info("Storing certificate request into " + filename);
            try (Writer writer = new FileWriter(filename)) {
                writer.write(reviewInfo.toXML());
            }

            System.out.println();
            System.out.println("Please review the certificate request in " + filename + ".");
            System.out.println("Update the file if necessary, then select an action below.");
            System.out.println();

            while (true) {
                System.out.print("Action (" + StringUtils.join(actions, "/") + "): ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                action = reader.readLine().trim().toLowerCase();

                if (actions.contains(action)) break;
            }

            logger.info("Loading certificate request from " + filename);
            String xml = new String(Files.readAllBytes(Paths.get(filename)));
            reviewInfo = CertReviewResponse.fromXML(xml);
        }

        if (action.equalsIgnoreCase("approve")) {
            certClient.approveRequest(requestId, reviewInfo);
            MainCLI.printMessage("Approved certificate request " + requestId);

        } else if (action.equalsIgnoreCase("reject")) {
            certClient.rejectRequest(requestId, reviewInfo);
            MainCLI.printMessage("Rejected certificate request " + requestId);

        } else if (action.equalsIgnoreCase("cancel")) {
            certClient.cancelRequest(requestId, reviewInfo);
            MainCLI.printMessage("Canceled certificate request " + requestId);

        } else if (action.equalsIgnoreCase("update")) {
            certClient.updateRequest(requestId, reviewInfo);
            MainCLI.printMessage("Updated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("validate")) {
            certClient.validateRequest(requestId, reviewInfo);
            MainCLI.printMessage("Validated certificate request " + requestId);

        } else if (action.equalsIgnoreCase("assign")) {
            certClient.assignRequest(requestId, reviewInfo);
            MainCLI.printMessage("Assigned certificate request " + requestId);

        } else if (action.equalsIgnoreCase("unassign")) {
            certClient.unassignRequest(requestId, reviewInfo);
            MainCLI.printMessage("Unassigned certificate request " + requestId);

        } else {
            throw new Exception("Invalid action: " + action);
        }

        CertRequestInfo certRequest = certClient.getRequest(requestId);
        CACertRequestCLI.printCertRequestInfo(certRequest);
    }
}
