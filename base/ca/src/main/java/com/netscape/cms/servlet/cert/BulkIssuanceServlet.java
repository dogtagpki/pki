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
package com.netscape.cms.servlet.cert;

import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

@WebServlet(
        name = "cabulkissuance",
        urlPatterns = "/agent/ca/bulkissuance",
        initParams = {
                @WebInitParam(name="unauthorizedTemplate",    value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="rejectedTemplate",        value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="svcpendingTemplate",      value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="resourceID",              value="certServer.ca.request.enrollment"),
                @WebInitParam(name="GetClientCert",           value="true"),
                @WebInitParam(name="authority",               value="ca"),
                @WebInitParam(name="interface",               value="agent"),
                @WebInitParam(name="ID",                      value="cabulkissuance"),
                @WebInitParam(name="errorTemplate",           value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="unexpectedErrorTemplate", value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="pendingTemplate",         value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="AuthzMgr",                value="BasicAclAuthz"),
                @WebInitParam(name="successTemplate",         value="/agent/ca/bulkissuance.template"),
                @WebInitParam(name="AuthMgr",                 value="certUserDBAuthMgr")
        }
)
public class BulkIssuanceServlet extends EnrollServlet {
    private static final long serialVersionUID = 1L;
}
