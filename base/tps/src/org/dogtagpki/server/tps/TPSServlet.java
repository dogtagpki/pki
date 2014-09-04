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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.tps.TPSConnection;

import com.netscape.certsrv.apps.CMS;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSServlet extends HttpServlet {

    private static final long serialVersionUID = -1092227495262381074L;

    public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String encoding = request.getHeader("Transfer-Encoding");

        CMS.debug("Encoding: " + encoding);

        if (encoding.equals("chunked") == false) {
            throw new IOException("TPSServlet.service: incorrect encoding! ");
        }

        response.setHeader("Transfer-Encoding", "chunked");

        TPSConnection con = new TPSConnection(
                request.getInputStream(), response.getOutputStream(), true);

        CMS.debug("TPSConnection created: " + con);

        String ipAddress = request.getRemoteAddr();

        TPSSession session = new TPSSession(con, ipAddress);

        CMS.debug("TPSSession created: " + session);

        session.process();

        CMS.debug("After session.process() exiting ...");

    }
}
