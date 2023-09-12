package com.netscape.cms.servlet.base;
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

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

@WebServlet(
        name = "ocspindex",
        urlPatterns = "/agent/index",
        initParams = {
                @WebInitParam(name="ID",            value="ocspindex"),
                @WebInitParam(name="template",      value="/agent/index.template"),
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr")
        }
)
public class OCSPIndexServlet extends IndexServlet {
    private static final long serialVersionUID = 1L;
}
