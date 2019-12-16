package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestValidateCLI extends CACertRequestActionCLI {

    public CACertRequestValidateCLI(CACertRequestCLI certRequestCLI) {
        super("validate", "Validate certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) throws Exception {

        certClient.validateRequest(requestId, reviewInfo);
        MainCLI.printMessage("Validated certificate request " + requestId);
    }
}
