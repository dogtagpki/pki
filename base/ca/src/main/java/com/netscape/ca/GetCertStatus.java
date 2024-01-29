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

import java.math.BigInteger;
import java.security.Principal;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class GetCertStatus implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetCertStatus.class);

    public GetCertStatus() {
    }

    @Override
    public boolean service(Request request) throws EBaseException {
        BigInteger serialno = request.getExtDataInBigInteger("serialNumber");
        String issuerDN = request.getExtDataInString("issuerDN");

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();
        CertificateAuthority ca = engine.getCA();

        String status = null;

        if (serialno != null) {
            CertRecord record = null;

            try {
                record = certDB.readCertificateRecord(serialno);
            } catch (EBaseException ee) {
                logger.warn(ee.toString());
            }

            if (record != null) {
                status = record.getStatus();
                if (status.equals("VALID")) {
                    X509CertImpl cacert = ca.getCACert();
                    Principal p = cacert.getSubjectName();

                    if (!p.toString().equals(issuerDN)) {
                        status = "INVALIDCERTROOT";
                    }
                }
            }
        }

        request.setExtData(Request.CERT_STATUS, status);
        return true;
    }
}
