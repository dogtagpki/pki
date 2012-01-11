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
// (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.filter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;

public class EERequestFilter implements Filter {
    private static final String HTTP_SCHEME = "http";
    private static final String HTTP_PORT = "http_port";
    private static final String HTTP_ROLE = "EE";
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTPS_PORT = "https_port";
    private static final String HTTPS_ROLE = "EE";
    private static final String PROXY_PORT = "proxy_port";
    private static final String PROXY_HTTP_PORT = "proxy_http_port";

    private FilterConfig config;

    /* Create a new EERequestFilter */
    public EERequestFilter() {
    }

    public void init(FilterConfig filterConfig)
                throws ServletException {
        this.config = filterConfig;
    }

    public void doFilter(ServletRequest request,
                          ServletResponse response,
                          FilterChain chain)
                throws java.io.IOException,
                       ServletException {
        String filterName = getClass().getName();

        String scheme = null;
        int port = 0;

        String request_port = null;
        String param_http_port = null;
        String param_https_port = null;
        String param_proxy_port = null;
        String param_proxy_http_port = null;
        String msg = null;
        String param_active = null;

        // CMS.debug("Entering the EE filter");
        param_active = config.getInitParameter("active");

        if (request instanceof HttpServletRequest) {
            HttpServletResponse resp = (HttpServletResponse) response;

            // RFC 1738:  verify that scheme is either "http" or "https"
            scheme = request.getScheme();
            if ((!scheme.equals(HTTP_SCHEME)) &&
                    (!scheme.equals(HTTPS_SCHEME))) {
                msg = "The scheme MUST be either '" + HTTP_SCHEME
                        + "' or '" + HTTPS_SCHEME
                        + "', NOT '" + scheme + "'!";
                CMS.debug(filterName + ":  " + msg);
                resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
                return;
            }

            // Always obtain either an "http" or an "https" port from request
            port = request.getLocalPort();
            request_port = Integer.toString(port);

            // Always obtain the "http" port passed in as a parameter
            param_http_port = config.getInitParameter(HTTP_PORT);
            if (param_http_port == null) {
                msg = "The <param-name> '" + HTTP_PORT
                        + "' </param-name> " + "MUST be specified in 'web.xml'!";
                CMS.debug(filterName + ":  " + msg);
                resp.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, msg);
                return;
            }

            // Always obtain the "https" port passed in as a parameter
            param_https_port = config.getInitParameter(HTTPS_PORT);
            if (param_https_port == null) {
                msg = "The <param-name> '" + HTTPS_PORT
                        + "' </param-name> " + "MUST be specified in 'web.xml'!";
                CMS.debug(filterName + ":  " + msg);
                resp.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, msg);
                return;
            }

            param_proxy_http_port = config.getInitParameter(PROXY_HTTP_PORT);
            param_proxy_port = config.getInitParameter(PROXY_PORT);
            boolean bad_port = false;

            // If the scheme is "http", compare
            // the request and param "http" ports;
            // otherwise, if the scheme is "https", compare
            // the request and param "https" ports
            if (scheme.equals(HTTP_SCHEME)) {
                if (!param_http_port.equals(request_port)) {
                    String uri = ((HttpServletRequest) request).getRequestURI();
                    if (param_proxy_http_port != null) {
                        if (!param_proxy_http_port.equals(request_port)) {
                            msg = "Use HTTP port '" + param_http_port
                                    + "' or proxy port '" + param_proxy_http_port
                                    + "' instead of '" + request_port
                                    + "' when performing " + HTTP_ROLE + " tasks!";
                            bad_port = true;
                        }
                    } else {
                        msg = "Use HTTP port '" + param_http_port
                                + "' instead of '" + request_port
                                + "' when performing " + HTTP_ROLE + " tasks!";
                        bad_port = true;
                    }
                    if (bad_port) {
                        CMS.debug(filterName + ":  " + msg);
                        CMS.debug(filterName + ": uri is " + uri);
                        if ((param_active != null) && (param_active.equals("false"))) {
                            CMS.debug("Filter is disabled .. continuing");
                        } else {
                            resp.sendError(HttpServletResponse.SC_NOT_FOUND, msg);
                            return;
                        }
                    }
                }
            } else if (scheme.equals(HTTPS_SCHEME)) {
                if (!param_https_port.equals(request_port)) {
                    String uri = ((HttpServletRequest) request).getRequestURI();
                    if (param_proxy_port != null) {
                        if (!param_proxy_port.equals(request_port)) {
                            msg = "Use HTTPS port '" + param_https_port
                                    + "' or proxy port '" + param_proxy_port
                                    + "' instead of '" + request_port
                                    + "' when performing " + HTTPS_ROLE + " tasks!";
                            bad_port = true;
                        }
                    } else {
                        msg = "Use HTTPS port '" + param_https_port
                                + "' instead of '" + request_port
                                + "' when performing " + HTTPS_ROLE + " tasks!";
                        bad_port = true;
                    }
                    if (bad_port) {
                        CMS.debug(filterName + ":  " + msg);
                        CMS.debug(filterName + ": uri is " + uri);
                        if ((param_active != null) && (param_active.equals("false"))) {
                            CMS.debug("Filter is disabled .. continuing");
                        } else {
                            resp.sendError(HttpServletResponse.SC_NOT_FOUND, msg);
                            return;
                        }
                    }
                }
            }

        }
        // CMS.debug("Exiting the EE filter");

        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
