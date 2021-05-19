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

package org.dogtagpki.server.kra.rest;

import java.net.URI;

import javax.ws.rs.core.Response;

import org.dogtagpki.kra.KRASystemCertResource;
import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.cert.CertData;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.kra.KeyRecoveryAuthority;
import com.netscape.kra.TransportKeyUnit;

/**
 * @author alee
 */
public class KRASystemCertService extends PKIService implements KRASystemCertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRASystemCertService.class);

    @Override
    public Response getTransportCert() throws Exception {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        TransportKeyUnit tu = (TransportKeyUnit) kra.getTransportKeyUnit();

        X509Certificate[] chain = tu.getChain();
        X509CertImpl[] chainImpl = new X509CertImpl[chain.length];

        for (int i=0; i<chain.length; i++) {
            X509Certificate c = chain[i];
            chainImpl[i] = new X509CertImpl(c.getEncoded());
        }

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                chainImpl,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);

        URI uri = uriInfo.getRequestUri();
        certData.setLink(new Link("self", uri));

        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, certData, request);
    }
}
