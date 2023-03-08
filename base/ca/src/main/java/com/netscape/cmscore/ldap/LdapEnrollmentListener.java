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
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

public class LdapEnrollmentListener implements IRequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapEnrollmentListener.class);

    private CAPublisherProcessor processor;

    public LdapEnrollmentListener(CAPublisherProcessor processor) {
        this.processor = processor;
    }

    @Override
    public void init(Subsystem sys, ConfigStore config) throws EBaseException {
    }

    @Override
    public void set(String name, String val) {
    }

    @Override
    public void accept(Request r) {

        logger.info("LdapEnrollmentListener: Handling enrollment request " + r.getRequestId().toHexString());

        String profileId = r.getExtDataInString(Request.PROFILE_ID);

        if (profileId == null) {
            // in case it's not meant for us
            if (r.getExtDataInInteger(Request.RESULT) == null) {
                return;
            }

            // check if request failed.
            if ((r.getExtDataInInteger(Request.RESULT)).equals(Request.RES_ERROR)) {
                logger.warn("Nothing to publish for enrollment request " + r.getRequestId().toHexString());
                return;
            }
        }

        logger.debug("LdapEnrollmentListener: Checking publishing for request " + r.getRequestId().toHexString());

        // check if issued certs is set.
        Certificate[] certs = null;

        if (profileId == null) {
            certs = r.getExtDataInCertArray(Request.ISSUED_CERTS);
        } else {
            certs = new Certificate[1];
            certs[0] = r.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
        }

        if (certs == null || certs.length == 0 || certs[0] == null) {
            logger.warn("No certs to publish for request " + r.getRequestId().toHexString());
            return;
        }

        if (certs[0] instanceof X509CertImpl) {
            acceptX509(r, certs);
        }
    }

    public void acceptX509(Request r, Certificate[] certs) {

        Integer[] results = new Integer[certs.length];
        Integer status = Request.RES_SUCCESS;

        for (int i = 0; i < certs.length; i++) {

            X509CertImpl xcert = (X509CertImpl) certs[i];

            if (xcert == null) {
                continue;
            }

            CertId certID = new CertId(xcert.getSerialNumber());

            try {
                processor.publishCert(xcert, r);
                results[i] = Request.RES_SUCCESS;

                logger.debug("LdapEnrollmentListener: Published cert " + certID.toHexString());
                // processor.setPublishedFlag(xcert.getSerialNumber(), true);

            } catch (ELdapException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH", certID.toHexString(), e.toString()), e);
                results[i] = Request.RES_ERROR;
                status = Request.RES_ERROR;
            }
        }

        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus", status);
    }
}
