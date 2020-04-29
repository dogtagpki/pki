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

package org.dogtagpki.server.rest;

import java.security.Principal;
import java.util.Date;

import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author alee
 */
public class SystemCertService extends PKIService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SystemCertService.class);

    public CertData createCertificateData(X509CertImpl cert, byte[] pkcs7bytes) throws Exception {

        CertData data = new CertData();

        data.setSerialNumber(new CertId(cert.getSerialNumber()));

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) data.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) data.setSubjectDN(subjectDN.toString());

        Date notBefore = cert.getNotBefore();
        if (notBefore != null) data.setNotBefore(notBefore.toString());

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) data.setNotAfter(notAfter.toString());

        String b64 = Cert.HEADER + "\n" + Utils.base64encodeMultiLine(cert.getEncoded()) + Cert.FOOTER + "\n";
        data.setEncoded(b64);

        String pkcs7str = Utils.base64encodeSingleLine(pkcs7bytes);
        data.setPkcs7CertChain(pkcs7str);

        return data;
    }
}
