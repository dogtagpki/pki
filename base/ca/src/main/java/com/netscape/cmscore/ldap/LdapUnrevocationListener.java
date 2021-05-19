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

import java.math.BigInteger;
import java.security.cert.Certificate;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;

public class LdapUnrevocationListener implements IRequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapUnrevocationListener.class);

    private CAPublisherProcessor processor;

    public LdapUnrevocationListener(CAPublisherProcessor processor) {
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

        logger.info("LdapUnrevocationListener: Handling unrevoke request " + r.getRequestId());

        // get fields in request.
        Certificate[] certs = r.getExtDataInCertArray(IRequest.OLD_CERTS);

        if (certs == null || certs.length == 0 || certs[0] == null) {
            // no certs in unrevoke.
            logger.warn("Nothing to publish for unrevocation request " + r.getRequestId());
            return;
        }

        acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] certs) {

        CAEngine engine = CAEngine.getInstance();

        Integer[] results = new Integer[certs.length];
        Integer status = IRequest.RES_SUCCESS;

        for (int i = 0; i < certs.length; i++) {

            X509CertImpl xcert = (X509CertImpl) certs[i];
            results[i] = IRequest.RES_ERROR;

            try {
                // We need the enrollment request to sort out predicate
                BigInteger serial = xcert.getSerialNumber();
                CertRecord certRecord = null;
                IAuthority auth = processor.getAuthority();

                if (auth == null || !(auth instanceof ICertificateAuthority)) {
                    logger.warn("LdapUnrevocationListener: Trying to get a cert from non cert authority");

                } else {
                    CertificateRepository certdb = ((ICertificateAuthority) auth).getCertificateRepository();

                    if (certdb == null) {
                        logger.warn("LdapUnrevocationListener: Missing cert database for " + auth);
                    } else {
                        try {
                            certRecord = certdb.readCertificateRecord(serial);
                        } catch (EBaseException e) {
                            logger.warn(CMS.getLogMessage("CMSCORE_LDAP_GET_CERT_RECORD", serial.toString(16), e.toString()), e);
                        }
                    }
                }

                MetaInfo metaInfo = null;
                String ridString = null;

                if (certRecord != null) {
                    metaInfo = (MetaInfo) certRecord.get(CertRecord.ATTR_META_INFO);
                }

                if (metaInfo == null) {
                    logger.warn("LdapUnrevocationListener: Unable to get meta info for cert 0x" + serial.toString(16));
                } else {
                    ridString = (String) metaInfo.get(CertRecord.META_REQUEST_ID);
                }

                IRequest req = null;

                if (ridString != null) {
                    RequestId rid = new RequestId(ridString);
                    req = engine.getRequestRepository().readRequest(rid);
                }

                processor.publishCert(xcert, req);

                results[i] = IRequest.RES_SUCCESS;
                logger.debug("LdapUnrevocationListener: Published cert 0x" + xcert.getSerialNumber().toString(16));

            } catch (ELdapException e) {
                status = IRequest.RES_ERROR;
                logger.warn(CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH", xcert.getSerialNumber().toString(16), e.toString()), e);

            } catch (EBaseException e) {
                status = IRequest.RES_ERROR;
                logger.warn(CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_FIND", xcert.getSerialNumber().toString(16), e.toString()), e);
            }
        }

        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus", status);
    }
}
