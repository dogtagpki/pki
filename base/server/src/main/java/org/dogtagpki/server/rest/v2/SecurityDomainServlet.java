//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.rest.base.SecurityDomainServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class SecurityDomainServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(SecurityDomainServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {"installToken"})
    public void getInstallToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.getInstallToken(): session: {}", session.getId());
        String hostname = request.getParameter("hostname");
        String subsystem = request.getParameter("subsystem");
        if (subsystem == null || subsystem.isBlank()) {
            throw new BadRequestException("Missing subsystem parameter");
        }
        PrintWriter out = response.getWriter();
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        InstallToken token = sdServlet.getInstallToken(hostname, subsystem, request.getUserPrincipal().getName());
        out.println(token.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"domainInfo"})
    public void getDomainInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.getDomainInfo(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        DomainInfo domain = sdServlet.getDomainInfo();
        out.println(domain.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"hosts"})
    public void getHosts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.getHosts(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        Collection<SecurityDomainHost> hosts = sdServlet.getHosts();
        ObjectMapper mapper = new ObjectMapper();
        out.println(mapper.writeValueAsString(hosts));
    }

    @WebAction(method = HttpMethod.GET, paths = {"hosts/{}"})
    public void getHost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.getHost(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String hostId = pathElement[1];
        PrintWriter out = response.getWriter();
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        SecurityDomainHost host = sdServlet.getHost(hostId);
        out.println(host.toJSON());
    }

    @WebAction(method = HttpMethod.PUT, paths = {"hosts"})
    public void addHost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.addHost(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        SecurityDomainHost host = JSONSerializer.fromJSON(requestData, SecurityDomainHost.class);
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        sdServlet.addHost(host);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"hosts/{}"})
    public void removeHost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SecurityDomainServlet.removeHost(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String hostId = pathElement[1];
        SecurityDomainServletBase sdServlet = new SecurityDomainServletBase(getEngine(), request.getLocale());
        sdServlet.removeHost(hostId);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
