package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestUpdateCLI extends CACertRequestActionCLI {

    public CACertRequestUpdateCLI(CACertRequestCLI certRequestCLI) {
        super("update", "Update certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) {

        certClient.updateRequest(requestId, reviewInfo);
        MainCLI.printMessage("Updated certificate request " + requestId);
    }
}
