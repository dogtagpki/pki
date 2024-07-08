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

import jakarta.ws.rs.core.Response;

import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoResource;
import org.dogtagpki.server.PKIEngine;

import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class InfoService extends PKIService implements InfoResource {

    @Override
    public Response getInfo() throws Exception {

        PKIEngine engine = (PKIEngine) servletContext.getAttribute("engine");
        Info info = engine.getInfo(servletRequest);

        return createOKResponse(info);
    }
}
