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

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Date;

import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.request.Request;

public class CertRequestInfoFactory {

    public static CertRequestInfo create(Request request) throws SecurityException {

        CertRequestInfo info = new CertRequestInfo();

        RequestId requestId = request.getRequestId();
        info.setRequestID(requestId);

        String requestType = request.getRequestType();
        RequestStatus requestStatus = request.getRequestStatus();

        info.setRequestType(requestType);
        info.setRequestStatus(requestStatus);

        info.setCertRequestType(request.getExtDataInString("cert_request_type"));

        Integer result = request.getExtDataInInteger(Request.RESULT);
        if (result == null || result.equals(Request.RES_SUCCESS)) {
            info.setOperationResult(CertRequestInfo.RES_SUCCESS);
        } else {
            info.setOperationResult(CertRequestInfo.RES_ERROR);
        }

        String error = request.getExtDataInString(Request.ERROR);
        info.setErrorMessage(error);

        if (requestType != null && requestStatus == RequestStatus.COMPLETE) {

            X509CertImpl impl = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
            if (impl == null && requestType.equals(Request.REVOCATION_REQUEST)) {
                // revocation request; try and get serial of revoked cert
                X509CertImpl[] certs =
                    request.getExtDataInCertArray(Request.OLD_CERTS);
                if (certs != null && certs.length > 0)
                    impl = certs[0];
            }

            if (impl != null) {
                BigInteger serialNo = impl.getSerialNumber();
                info.setCertId(new CertId(serialNo));
            }
        }

        Date creationTime = request.getCreationTime();
        info.setCreationTime(creationTime);

        Date modificationTime = request.getModificationTime();
        info.setModificationTime(modificationTime);

        return info;
    }

    public static CertRequestInfo create(Request request, UriInfo uriInfo) throws SecurityException, NoSuchMethodException {

        CertRequestInfo info = create(request);

        Method getRequestInfo = CertRequestResource.class.getMethod("getRequestInfo", RequestId.class);
        Path certRequestPath = getRequestInfo.getAnnotation(Path.class);

        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path(certRequestPath.value());
        info.setRequestURL(reqBuilder.build(info.getRequestID()).toString());

        Method getCert = CertResource.class.getMethod("getCert", CertId.class);
        Path certPath = getCert.getAnnotation(Path.class);

        UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
        certBuilder.path(certPath.value());

        CertId certID = info.getCertId();
        if (certID != null) {
            BigInteger serialNo = info.getCertId().toBigInteger();
            info.setCertURL(certBuilder.build(serialNo).toString());
        }

        return info;
    }
}
