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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.ocsp.OCSPAuthority;

@WebServlet(
        name = "ocspOCSP",
        urlPatterns = {
                "/ee/ocsp",
                "/ee/ocsp/*"
        },
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ocsp"),
                @WebInitParam(name="ID",            value="ocspOCSP"),
                @WebInitParam(name="resourceID",    value="certServer.ee.request.ocsp")
        }
)
public class OCSPOCSPServlet extends OCSPServlet {

    private static final long serialVersionUID = 1L;

    OCSPAuthority ocsp;

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        ocsp = (OCSPAuthority) mAuthority;
    }

    public OCSPResponse validate(OCSPRequest ocspRequest) throws EBaseException {
        return ocsp.validate(ocspRequest);
    }
}
