package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class CACertRequestShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestShowCLI.class);

    CACertRequestCLI certRequestCLI;

    public CACertRequestShowCLI(CACertRequestCLI certRequestCLI) {
        super("show", "Show certificate request", certRequestCLI);
        this.certRequestCLI = certRequestCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CACertClient certClient = certRequestCLI.getCertClient(client);
        CertRequestInfo certRequest = certClient.getRequest(requestId);

        MainCLI.printMessage("Certificate request \"" + requestId.toHexString() + "\"");
        CACertRequestCLI.printCertRequestInfo(certRequest);
    }
}
