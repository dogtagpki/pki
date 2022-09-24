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
package com.netscape.ca;

import java.security.cert.CRLException;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.request.Request;

class ServiceGetCRL implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceGetCRL.class);

    public ServiceGetCRL(CAService service) {
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        try {
            CAEngine engine = CAEngine.getInstance();
            CRLRepository crlRepository = engine.getCRLRepository();

            CRLIssuingPointRecord crlRec = crlRepository.readCRLIssuingPointRecord(CertificateAuthority.PROP_MASTER_CRL);
            X509CRLImpl crl = new X509CRLImpl(crlRec.getCRL());

            request.setExtData(Request.CRL, crl.getEncoded());

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_FIND_CRL"), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOT_FOUND", e.toString()), e);

        } catch (CRLException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_INST_CRL", CertificateAuthority.PROP_MASTER_CRL), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOGOOD", CertificateAuthority.PROP_MASTER_CRL), e);

        } catch (X509ExtensionException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_NO_ISSUING_REC"), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_EXT_NOGOOD",
                            CertificateAuthority.PROP_MASTER_CRL), e);
        }
        return true;
    }
}
