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

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertResource;
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

        //Get Cert info if issued.

        String serialNoStr = null;

        if (requestType != null && requestStatus == RequestStatus.COMPLETE) {
            X509CertImpl impl[] = new X509CertImpl[1];
            impl[0] = request.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

            BigInteger serialNo;
            if (impl[0] != null) {
                serialNo = impl[0].getSerialNumber();
                serialNoStr = serialNo.toString();
            }
        }

        if (!StringUtils.isEmpty(serialNoStr)) {
            Path certPath = CertResource.class.getAnnotation(Path.class);
            UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
            certBuilder.path(certPath.value() + "/" + serialNoStr);
            info.setCertURL(certBuilder.build().toString());
        }

        return info;
    }
}
