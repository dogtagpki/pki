//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.request.model;

import java.math.BigInteger;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.request.CertRequestResource;

public class CertRequestInfoFactory {

    public static final String REQ_COMPLETE = "complete";

    public static CertRequestInfo create(IRequest request, UriInfo uriInfo) {
        CertRequestInfo ret = new CertRequestInfo();
        String requestType = request.getRequestType();
        String requestStatus = request.getRequestStatus().toString();

        ret.setRequestType(requestType);
        ret.setRequestStatus(requestStatus);

        ret.setCertRequestType(request.getExtDataInString("cert_request_type"));

        Path certRequestPath = CertRequestResource.class.getAnnotation(Path.class);
        RequestId rid = request.getRequestId();

        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path(certRequestPath.value() + "/" + rid);
        ret.setRequestURL(reqBuilder.build().toString());

        //Get cert info if issued.
        String serialNoStr = null;

        if ((requestType != null) && (requestStatus != null)) {
            if (requestStatus.equals(REQ_COMPLETE)) {
                X509CertImpl impl[] = new X509CertImpl[1];
                impl[0] = request.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

                BigInteger serialNo;
                if (impl[0] != null) {
                    serialNo = impl[0].getSerialNumber();
                    serialNoStr = serialNo.toString();
                }
            }

        }

        if (serialNoStr != null && !serialNoStr.equals("")) {
            Path certPath = CertResource.class.getAnnotation(Path.class);
            UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
            certBuilder.path(certPath.value() + "/" + serialNoStr);
            ret.setCertURL(certBuilder.build().toString());
        }
        return ret;
    }

}
