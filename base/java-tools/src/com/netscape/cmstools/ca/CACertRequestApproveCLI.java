package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestApproveCLI extends CACertRequestActionCLI {

    public CACertRequestApproveCLI(CACertRequestCLI certRequestCLI) {
        super("approve", "Approve certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) {

        certClient.approveRequest(requestId, reviewInfo);
        MainCLI.printMessage("Approved certificate request " + requestId);
    }
}
