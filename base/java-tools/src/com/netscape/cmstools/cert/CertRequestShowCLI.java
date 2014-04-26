package com.netscape.cmstools.cert;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestShowCLI extends CLI {

    CertCLI certCLI;

    public CertRequestShowCLI(CertCLI certCLI) {

        super("request-show", "Show certificate request", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> [OPTIONS...]", options);
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

        CertRequestInfo certRequest = certCLI.certClient.getRequest(requestId);

        MainCLI.printMessage("Certificate request \"" + requestId + "\"");
        CertCLI.printCertRequestInfo(certRequest);
    }
}
