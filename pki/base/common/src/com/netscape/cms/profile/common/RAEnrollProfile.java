// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.common;


import java.security.cert.*;
import java.math.*;
import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.connector.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.ra.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;

import java.security.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;


/**
 * This class implements a Registration Manager 
 * enrollment profile.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class RAEnrollProfile extends EnrollProfile {

    public RAEnrollProfile() {
        super();
    }

    public IAuthority getAuthority() {
        IAuthority authority = (IAuthority) 
            CMS.getSubsystem(CMS.SUBSYSTEM_RA);

        if (authority == null)
            return null;
        return authority;
    }

    public X500Name getIssuerName() {
        IRegistrationAuthority ra = (IRegistrationAuthority)
            CMS.getSubsystem(CMS.SUBSYSTEM_RA);
        X500Name issuerName = ra.getX500Name();

        return issuerName;
    }

    public void execute(IRequest request)
        throws EProfileException {


        if (!isEnable()) {
            CMS.debug("CAEnrollProfile: Profile Not Enabled");
            throw new EProfileException("Profile Not Enabled");
        }

        IRegistrationAuthority ra =
            (IRegistrationAuthority) getAuthority();
        IRAService raService = (IRAService) ra.getRAService();

        if (raService == null) {
            throw new EProfileException("No RA Service");
        }


        IRequestQueue queue = ra.getRequestQueue();

        // send request to CA
        try {
            IConnector caConnector = raService.getCAConnector();

            if (caConnector == null) {
                CMS.debug("RAEnrollProfile: CA connector not configured");
            } else {
                caConnector.send(request);
                // check response
                if (!request.isSuccess()) { 
                    CMS.debug("RAEnrollProfile error talking to CA setting req status to SVC_PENDING");

                    request.setRequestStatus(RequestStatus.SVC_PENDING);

                    try {
                       queue.updateRequest(request);
                    } catch (EBaseException e) {
                        CMS.debug("RAEnrollProfile: Update request " + e.toString());
                    }
                    throw new ERejectException(
                            request.getError(getLocale(request)));
                }
            }
        } catch (Exception e) {
            CMS.debug("RAEnrollProfile: " + e.toString());
            throw new EProfileException(e.toString());
        }

        // request handling
        Enumeration names = ra.getRequestListenerNames();

        if (names != null) {
            while (names.hasMoreElements()) {
                String name = (String) names.nextElement();

                CMS.debug("CAEnrollProfile: listener " + name);
                IRequestListener listener = ra.getRequestListener(name);

                if (listener != null) {
                    listener.accept(request);
                }
            }
        }
    }
}
