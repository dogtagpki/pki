package com.netscape.cms.servlet.admin;
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

import org.dogtagpki.server.tks.TKSEngine;

import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.tks.TKSAuthority;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
@WebServlet(
        name = "tksserver",
        urlPatterns = "/server",
        initParams = {
                @WebInitParam(name="ID",       value="tksserver"),
                @WebInitParam(name="AuthzMgr", value="BasicAclAuthz")
        }
)
public class TKSCMSAdminServlet extends CMSAdminServlet {

    private static final long serialVersionUID = 1L;

    @Override
    void readSubsystem(NameValuePairs params) {

        TKSEngine engine = TKSEngine.getInstance();
        TKSAuthority tks = (TKSAuthority) engine.getSubsystem(TKSAuthority.ID);

        params.put(tks.getId(), Constants.PR_TKS_INSTANCE);
    }
}
