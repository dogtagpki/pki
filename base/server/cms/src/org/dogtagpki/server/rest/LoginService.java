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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest;

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.LoginResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class LoginService extends PKIService implements LoginResource {

    private static Logger logger = LoggerFactory.getLogger(LoginService.class);

    @Override
    public Response login() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("LoginService.login(): session: " + session.getId());

        // mark banner displayed in this session
        session.setAttribute("bannerDisplayed", "true");

        return createNoContentResponse();
    }
}
