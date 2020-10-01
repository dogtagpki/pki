package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestAssignCLI extends CACertRequestActionCLI {

    public CACertRequestAssignCLI(CACertRequestCLI certRequestCLI) {
        super("assign", "Assign certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) throws Exception {

        certClient.assignRequest(requestId, reviewInfo);
        MainCLI.printMessage("Assigned certificate request " + requestId);
    }
}
