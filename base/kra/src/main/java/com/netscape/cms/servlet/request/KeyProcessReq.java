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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ArgBlock;

/**
 * Display key request detail to the user.
 */
@WebServlet(
        name = "kraKRAProcessReq",
        urlPatterns = "/agent/kra/processReq",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="parser",        value="KeyReqParser.PARSER"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="templatePath",  value="/agent/kra/processReq.template"),
                @WebInitParam(name="ID",            value="kraKRAProcessReq"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.kra.request")
        }
)
public class KeyProcessReq extends ProcessReq {

    public KeyProcessReq() {
    }

    /**
     * Initialize the servlet. This servlet uses the template file
     * "processReq.template" to process the response.
     * The initialization parameter 'parser' is read from the
     * servlet configuration, and is used to set the type of request.
     * The value of this parameter can be:
     * <UL>
     * <LI><B>KeyReqParser.PARSER</B> - Show key archival detail
     * </UL>
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
    public void addAuthorityName(ArgBlock header) throws EBaseException {
        header.addStringValue("localkra", "yes");
    }
}
