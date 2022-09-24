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

import java.util.Enumeration;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceGetCertificates implements IServant {

    public ServiceGetCertificates(CAService service) {
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        Enumeration<String> enum1 = request.getExtDataKeys();

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();

            if (name.equals(Request.CERT_FILTER)) {
                String filter = request.getExtDataInString(Request.CERT_FILTER);
                X509CertImpl[] certs = certDB.getX509Certificates(filter);

                if (certs != null) {
                    request.setExtData(Request.OLD_CERTS, certs);
                }
            }
        }
        return true;
    }
}
