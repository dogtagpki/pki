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
package com.netscape.cms.servlet.connector;

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

@WebServlet(
        name = "kraConnector",
        urlPatterns = "/agent/kra/connector",
        initParams = {
                @WebInitParam(name="GetClientCert",  value="true"),
                @WebInitParam(name="AuthzMgr",       value="BasicAclAuthz"),
                @WebInitParam(name="authority",      value="kra"),
                @WebInitParam(name="ID",             value="kraConnector"),
                @WebInitParam(name="RequestEncoder", value="com.netscape.cmscore.connector.HttpRequestEncoder"),
                @WebInitParam(name="resourceID",     value="certServer.kra.connector"),
                @WebInitParam(name="AuthMgr",        value="certUserDBAuthMgr")
        }
)
public class KRAConnectorServlet extends ConnectorServlet {
    private static final long serialVersionUID = 1L;
}
