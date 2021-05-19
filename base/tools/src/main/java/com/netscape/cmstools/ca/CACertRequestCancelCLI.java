package com.netscape.cmstools.ca;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class CACertRequestCancelCLI extends CACertRequestActionCLI {

    public CACertRequestCancelCLI(CACertRequestCLI certRequestCLI) {
        super("cancel", "Cancel certificate request", certRequestCLI);
    }

    @Override
    public void performAction(
            CACertClient certClient,
            RequestId requestId,
            CertReviewResponse reviewInfo) throws Exception {

        certClient.cancelRequest(requestId, reviewInfo);
        MainCLI.printMessage("Canceled certificate request " + requestId);
    }
}
