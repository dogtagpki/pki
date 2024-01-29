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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.request.Request;

class ServiceGetCAChain implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceGetCAChain.class);

    public ServiceGetCAChain() {
    }

    @Override
    public boolean service(Request request) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        CertificateChain certChain = ca.getCACertChain();
        ByteArrayOutputStream certChainOut = new ByteArrayOutputStream();
        try {
            certChain.encode(certChainOut);
        } catch (IOException e) {
            logger.error(e.toString(), e);
            throw new EBaseException(e.toString(), e);
        }
        request.setExtData(Request.CACERTCHAIN, certChainOut.toByteArray());
        return true;
    }
}
