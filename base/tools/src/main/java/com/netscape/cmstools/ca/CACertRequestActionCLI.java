package com.netscape.cmstools.ca;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class CACertRequestActionCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestActionCLI.class);

    CACertRequestCLI certRequestCLI;

    public CACertRequestActionCLI(
            String name,
            String description,
            CACertRequestCLI certRequestCLI) {
        super(name, description, certRequestCLI);
        this.certRequestCLI = certRequestCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "input-file", true, "Input file containing certificate request.");
        option.setArgName("filename");
        options.addOption(option);

        options.addOption(null, "force", false, "Force");
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

        String filename = cmd.getOptionValue("input-file");
        boolean force = cmd.hasOption("force");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CACertClient certClient = certRequestCLI.getCertClient(client);

        logger.info("Retrieving certificate request " + requestId.toHexString());
        CertReviewResponse reviewInfo = certClient.reviewRequest(requestId);

        // save new nonce
        String nonce = reviewInfo.getNonce();
        logger.info("Nonce: " + nonce);

        if (filename == null) {

            // if input file not provided, ask for confirmation (unless forced)
            // before performing the action on the request

            if (!force) {

                CACertRequestCLI.printCertReviewResponse(reviewInfo);

                System.out.println();
                System.out.print("Are you sure (y/N)? ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String confirmation = reader.readLine().trim();

                if (!confirmation.equalsIgnoreCase("y")) {
                    return;
                }
            }

        } else {

            // if input file provided, load updated request from file

            logger.info("Loading certificate request from " + filename);
            String json = new String(Files.readAllBytes(Paths.get(filename)));
            reviewInfo = JSONSerializer.fromJSON(json, CertReviewResponse.class);

            if (!requestId.equals(reviewInfo.getRequestId())) {
                throw new Exception("Incorrect certificate request in " + filename);
            }

            // replace old nonce with the new one
            reviewInfo.setNonce(nonce);
        }

        performAction(certClient, requestId, reviewInfo);

        CertRequestInfo certRequest = certClient.getRequest(requestId);
        CACertRequestCLI.printCertRequestInfo(certRequest);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) throws Exception {
    }
}
