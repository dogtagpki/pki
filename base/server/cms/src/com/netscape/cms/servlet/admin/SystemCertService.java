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

package com.netscape.cms.servlet.admin;

import java.security.cert.CertificateEncodingException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.certsrv.system.SystemCertResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * This is the class used to list, retrieve and modify system certificates for all Java subsystems.
 *
 * @author alee
 *
 */
public class SystemCertService extends PKIService implements SystemCertResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public SystemCertService() {
        CMS.debug("SystemCertService.<init>()");
    }

    /**
     * Used to retrieve the transport certificate
     */
    public Response getTransportCert() {
        CertData cert = null;
        IKeyRecoveryAuthority kra = null;

        // auth and authz

        kra = (IKeyRecoveryAuthority) CMS.getSubsystem("kra");
        if (kra == null) {
            // no KRA
            throw new ResourceNotFoundException("KRA subsystem not found.");
        }

        ITransportKeyUnit tu = kra.getTransportKeyUnit();
        if (tu == null) {
            CMS.debug("getTransportCert: transport key unit is null");
            throw new PKIException("No transport key unit.");
        }
        org.mozilla.jss.crypto.X509Certificate transportCert = tu.getCertificate();
        if (transportCert == null) {
            CMS.debug("getTransportCert: transport cert is null");
            throw new PKIException("Transport cert not found.");
        }
        try {
            cert = createCertificateData(transportCert);
        } catch (CertificateEncodingException e) {
            CMS.debug("getTransportCert: certificate encoding exception with transport cert");
            e.printStackTrace();
            throw new PKIException("Unable to encode transport cert");
        }
        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, cert, request);
    }

}
