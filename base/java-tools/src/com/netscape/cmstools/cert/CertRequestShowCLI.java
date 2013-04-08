package com.netscape.cmstools.cert;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestShowCLI extends CLI {

    CertCLI parent;

    public CertRequestShowCLI(CertCLI parent) {
        super("request-show", "Show certificate request");
        this.parent = parent;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <Request ID>", options);
    }

    @Override
    public void execute(String[] args) throws Exception {

        CommandLine cmd = null;
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

        CertRequestInfo certRequest = parent.client.getRequest(requestId);

        MainCLI.printMessage("Certificate request \"" + requestId + "\"");
        CertCLI.printCertRequestInfo(certRequest);
    }
}
