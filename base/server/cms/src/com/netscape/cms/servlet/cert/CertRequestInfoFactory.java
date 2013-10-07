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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.cert;

import java.math.BigInteger;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

public class CertRequestInfoFactory {

    public static CertRequestInfo create(IRequest request, UriInfo uriInfo) {

        CertRequestInfo info = new CertRequestInfo();

        String requestType = request.getRequestType();
        RequestStatus requestStatus = request.getRequestStatus();

        info.setRequestType(requestType);
        info.setRequestStatus(requestStatus);

        info.setCertRequestType(request.getExtDataInString("cert_request_type"));

        Path certRequestPath = CertRequestResource.class.getAnnotation(Path.class);
        RequestId requestId = request.getRequestId();

        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path(certRequestPath.value() + "/" + requestId);
        info.setRequestURL(reqBuilder.build().toString());

        Integer result = request.getExtDataInInteger(IRequest.RESULT);
        if (result == null || result.equals(IRequest.RES_SUCCESS)) {
            info.setOperationResult(CertRequestInfo.RES_SUCCESS);
        } else {
            info.setOperationResult(CertRequestInfo.RES_ERROR);
            String error = request.getExtDataInString(IRequest.ERROR);
            info.setErrorMessage(error);
        }

        if (requestType == null || requestStatus != RequestStatus.COMPLETE)
            return info;

        X509CertImpl impl = request.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
        if (impl == null)
            return info;

        BigInteger serialNo = impl.getSerialNumber();
        info.setCertId(new CertId(serialNo));

        Path certPath = CertResource.class.getAnnotation(Path.class);
        UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
        certBuilder.path(certPath.value() + "/" + serialNo);

        info.setCertURL(certBuilder.build().toString());

        return info;
    }
}
