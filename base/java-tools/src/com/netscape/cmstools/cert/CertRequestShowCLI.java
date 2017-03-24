package com.netscape.cmstools.cert;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.cert.CertClient;
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

        CertClient certClient = certCLI.getCertClient();
        CertRequestInfo certRequest = certClient.getRequest(requestId);

        MainCLI.printMessage("Certificate request \"" + requestId + "\"");
        CertCLI.printCertRequestInfo(certRequest);
    }
}
