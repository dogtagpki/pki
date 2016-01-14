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

package org.dogtagpki.server.rest;

import java.security.Principal;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.account.AccountInfo;
import com.netscape.certsrv.account.AccountResource;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class AccountService extends PKIService implements AccountResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    @Override
    public Response login() {
        HttpSession session = servletRequest.getSession();
        System.out.println("Creating session "+session.getId());

        Principal principal = servletRequest.getUserPrincipal();
        System.out.println("Principal: "+principal);

        AccountInfo response = new AccountInfo();
        String name = principal.getName();
        response.setID(name);

        if (principal instanceof PKIPrincipal) {
            PKIPrincipal pkiPrincipal = (PKIPrincipal)principal;
            IUser user = pkiPrincipal.getUser();

            String fullName = user.getFullName();
            if (!StringUtils.isEmpty(fullName)) response.setFullName(fullName);

            String email = user.getEmail();
            if (!StringUtils.isEmpty(email)) response.setEmail(email);
        }

        if (principal instanceof GenericPrincipal) {
            String[] roles = ((GenericPrincipal) principal).getRoles();
            response.setRoles(Arrays.asList(roles));
        }

        return createOKResponse(response);
    }

    @Override
    public Response logout() {
        HttpSession session = servletRequest.getSession(false);
        if (session == null) return createNoContentResponse();

        System.out.println("Destroying session "+session.getId());
        session.invalidate();

        return createNoContentResponse();
    }
}
