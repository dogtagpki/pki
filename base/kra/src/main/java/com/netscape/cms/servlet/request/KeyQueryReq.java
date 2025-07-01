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
package com.netscape.cms.servlet.request;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;

import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * Show paged list of key requests matching search criteria.
 */
@WebServlet(
        name = "krakraqueryReq",
        urlPatterns = "/agent/kra/queryReq",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="parser",        value="KeyReqParser.PARSER"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="templatePath",  value="/agent/kra/queryReq.template"),
                @WebInitParam(name="ID",            value="krakraqueryReq"),
                @WebInitParam(name="resourceID",    value="certServer.kra.requests"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr")
        }
)
public class KeyQueryReq extends QueryReq {

    private static final long serialVersionUID = 1L;

    public KeyQueryReq() {
    }

    /**
     * Initialize the servlet. This servlet uses the template file
     * "queryReq.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {

        super.init(sc);

        String tmp = sc.getInitParameter(PROP_PARSER);

        if (tmp != null) {
            if (tmp.trim().equals("KeyReqParser.PARSER")) {
                mParser = KeyReqParser.PARSER;
            }
        }
    }

    @Override
    public void validateAuthToken(HttpServletRequest request, AuthToken authToken) throws EBaseException {
        String realm = request.getParameter(REALM);
        mAuthz.checkRealm(realm, authToken, null, mAuthzResourceName, "list");
    }

    @Override
    public String getFilter(HttpServletRequest request) {

        String filter = super.getFilter(request);
        String realm = request.getParameter(REALM);

        if (realm != null) {
            filter = "(&" + filter + "(realm=" + LDAPUtil.escapeFilter(realm) +"))";
        } else {
            filter = "(&" + filter + "(!(realm=*)))";
        }

        return filter;
    }
}
