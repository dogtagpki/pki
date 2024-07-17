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
package com.netscape.cms.servlet.ocsp;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;

@WebServlet(
        name = "caOCSP",
        urlPatterns = {
                "/ocsp",
                "/ocsp/*"
        },
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="interface",     value="ee"),
                @WebInitParam(name="ID",            value="caOCSP"),
                @WebInitParam(name="resourceID",    value="certServer.ee.request.ocsp")
        }
)
public class CAOCSPServlet extends OCSPServlet {

    private static final long serialVersionUID = 1L;

    CertificateAuthority ca;

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        ca = (CertificateAuthority) mAuthority;
    }

    public OCSPResponse validate(OCSPRequest ocspRequest) throws EBaseException {
        CAEngine engine = (CAEngine) getCMSEngine();
        return engine.validate(ca, ocspRequest);
    }
}
