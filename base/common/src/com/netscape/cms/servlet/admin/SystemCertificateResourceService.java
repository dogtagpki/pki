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

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.cert.model.CertificateData;

/**
 * This is the class used to list, retrieve and modify system certificates for all Java subsystems.
 *
 * @author alee
 *
 */
public class SystemCertificateResourceService extends CMSResourceService implements SystemCertificateResource {

    /**
     * Used to retrieve the transport certificate
     */
    public Response getTransportCert() {
        CertificateData cert = null;
        IKeyRecoveryAuthority kra = null;

        // auth and authz

        kra = (IKeyRecoveryAuthority) CMS.getSubsystem("kra");
        if (kra == null) {
            // no KRA
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        ITransportKeyUnit tu = kra.getTransportKeyUnit();
        if (tu == null) {
            CMS.debug("getTransportCert: transport key unit is null");
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        org.mozilla.jss.crypto.X509Certificate transportCert = tu.getCertificate();
        if (transportCert == null) {
            CMS.debug("getTransportCert: transport cert is null");
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        try {
            cert = createCertificateData(transportCert);
        } catch (CertificateEncodingException e) {
            CMS.debug("getTransportCert: certificate encoding exception with transport cert");
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, cert);
    }

}
