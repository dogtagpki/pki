package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestUnassignCLI extends CACertRequestActionCLI {

    public CACertRequestUnassignCLI(CACertRequestCLI certRequestCLI) {
        super("unassign", "Unassign certificate request", certRequestCLI);
    }

    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) {

        certClient.unassignRequest(requestId, reviewInfo);
        MainCLI.printMessage("Unassigned certificate request " + requestId);
    }
}
