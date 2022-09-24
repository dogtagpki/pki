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

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class GetCertsForChallenge implements IServant {

    public GetCertsForChallenge(CAService service) {
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        BigInteger[] serialNoArray =
                request.getExtDataInBigIntegerArray(CAService.SERIALNO_ARRAY);
        if (serialNoArray == null) {
            throw new ECAException(CMS.getLogMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }
        X509CertImpl[] certs = new X509CertImpl[serialNoArray.length];

        for (int i = 0; i < serialNoArray.length; i++) {
            certs[i] = cr.getX509Certificate(serialNoArray[i]);
        }
        request.setExtData(Request.OLD_CERTS, certs);
        return true;
    }
}
