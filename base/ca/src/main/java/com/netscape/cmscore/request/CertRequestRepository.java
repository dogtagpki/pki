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
package com.netscape.cmscore.request;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.dbs.DBSubsystem;

public class CertRequestRepository extends RequestRepository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestRepository.class);

    public CertRequestRepository(DBSubsystem dbSubsystem) throws EBaseException {
        super(dbSubsystem, "(requeststate=*)");
    }

    public void updateRequest(
            IRequest request,
            X509CertInfo info,
            X509CertImpl cert) throws Exception {

        logger.info("CertRequestRepository: Updating cert request " + request.getRequestId());

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
        request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);
    }
}
