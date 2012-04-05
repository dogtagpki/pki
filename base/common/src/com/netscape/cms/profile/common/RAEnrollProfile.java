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

import java.util.Enumeration;

import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.ra.IRAService;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;

/**
 * This class implements a Registration Manager
 * enrollment profile.
 *
 * @version $Revision$, $Date$
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
        IRAService raService = ra.getRAService();

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
        Enumeration<String> names = ra.getRequestListenerNames();

        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();

                CMS.debug("CAEnrollProfile: listener " + name);
                IRequestListener listener = ra.getRequestListener(name);

                if (listener != null) {
                    listener.accept(request);
                }
            }
        }
    }
}
