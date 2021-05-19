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
package com.netscape.cmscore.ldap;

import java.security.cert.Certificate;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.cmscore.apps.CMS;

public class LdapRenewalListener implements IRequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapRenewalListener.class);

    private CAPublisherProcessor processor;

    public LdapRenewalListener(CAPublisherProcessor processor) {
        this.processor = processor;
    }

    @Override
    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
    }

    @Override
    public void set(String name, String val) {
    }

    @Override
    public void accept(IRequest r) {

        logger.info("LdapRenewalListener: Handling renewal request " + r.getRequestId());

        // Note we do not remove old certs from directory during renewal
        Certificate[] certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

        if (certs == null || certs.length == 0) {
            logger.warn("LdapRenewalListener: No certs to publish for renewal request " + r.getRequestId());
            return;
        }

        acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] certs) {

        Integer[] results = new Integer[certs.length];
        Integer status = IRequest.RES_SUCCESS;

        for (int i = 0; i < certs.length; i++) {

            X509CertImpl cert = (X509CertImpl) certs[i];

            if (cert == null) {
                continue; // there was an error issuing this cert.
            }

            try {
                processor.publishCert(cert, r);
                results[i] = IRequest.RES_SUCCESS;

                logger.info("LdapRenewalListener: Published cert 0x" + cert.getSerialNumber().toString(16));

            } catch (ELdapException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH", cert.getSerialNumber().toString(16), e.toString()), e);
                results[i] = IRequest.RES_ERROR;
                status = IRequest.RES_ERROR;
            }
        }
        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus", status);
    }
}
