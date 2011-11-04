package com.netscape.cmscore.request;

import java.util.Date;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.ldap.IRequestMod;

/**
 * Default testing stub for the IRequest interface.
 */
public class RequestModDefaultStub implements IRequestMod {
    public void modRequestStatus(IRequest r, RequestStatus s) {
    }

    public void modCreationTime(IRequest r, Date d) {
    }

    public void modModificationTime(IRequest r, Date d) {
    }
}
