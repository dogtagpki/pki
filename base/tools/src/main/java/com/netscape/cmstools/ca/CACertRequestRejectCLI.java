package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestRejectCLI extends CACertRequestActionCLI {

    public CACertRequestRejectCLI(CACertRequestCLI certRequestCLI) {
        super("reject", "Reject certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) throws Exception {

        certClient.rejectRequest(requestId, reviewInfo);
        MainCLI.printMessage("Rejected certificate request " + requestId);
    }
}
