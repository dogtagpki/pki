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

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSServlet extends HttpServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSServlet.class);
    private static final long serialVersionUID = -1092227495262381074L;

    public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String encoding = request.getHeader("Transfer-Encoding");
        String method = request.getMethod();

        logger.debug("Encoding: " + encoding);
        logger.debug("Method: " + method);

        if(!"POST".equals(method)) {
        	response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                logger.warn("Returning 405 Method Not Allowed - the HTTP method must be POST");
                return;
        }

        if(!"chunked".equals(encoding)) {
        	response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                logger.warn("Returning 400 Bad Request - Transfer-Encoding is not chunked");
        	return;
        }

        response.setHeader("Transfer-Encoding", "chunked");
        response.flushBuffer();

        TPSConnection con = new TPSConnection(
                request.getInputStream(), response.getOutputStream(), true);

        logger.debug("TPSConnection created: " + con);

        String ipAddress = request.getRemoteAddr();

        TPSSession session = new TPSSession(con, ipAddress);

        logger.debug("TPSSession created: " + session);

        session.process();

        logger.debug("After session.process() exiting ...");
    }
}
