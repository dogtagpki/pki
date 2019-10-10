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

package org.dogtagpki.server.ca.rest;

import java.net.URI;

import javax.ws.rs.core.Response;

import org.dogtagpki.ca.CASystemCertResource;
import org.dogtagpki.server.rest.SystemCertService;
import org.jboss.resteasy.plugins.providers.atom.Link;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;

/**
 * @author alee
 */
public class CASystemCertService extends SystemCertService implements CASystemCertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CASystemCertService.class);

    public Response getTransportCert() throws Exception {

        KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
        KRAConnectorInfo info = processor.getConnectorInfo();

        String encodedCert = info.getTransportCert();
        byte[] bytes = Utils.base64decode(encodedCert);
        X509CertImpl cert = new X509CertImpl(bytes);

        CertData certData = createCertificateData(cert);

        URI uri = uriInfo.getRequestUri();
        certData.setLink(new Link("self", uri));

        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, certData, request);
    }
}
