//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2.filters;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Comparator;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.MimeType;
import com.netscape.cmscore.apps.CMSEngine;

import org.dogtagpki.server.rest.ACLChecker;

/**
 * Basic ACL filter for REST APIs
 *
 * Subclasses can associate ACL to servlet, URLPatterns or specific endpoints. The {@link #setAcl(String)} method will assign a
 * default ACL to use for all the associated entities (servlet or pattern). To provide a finer grained ACL it is possible to specify
 * a map with the method {@link #setAclMap(Map)}. The map value is the ACL to use while the key is the endpoint where
 * the ACL has to be applied. The key formal is:
 *
 *    key= <method>:<path>
 *
 * The method is one of the HTTP method as defined in Java servlet request (e.g. GET, POST, etc.).
 * The path is the endpoint in the associated servlet where the ACL has to be applied. If there is a REST path param this can be indicated
 * with the sequence "{}".
 *
 * Example of ACL a servlet handking token could be:
 *
 *   default acl: token.read
 *
 *   ACLMap:
 *
 *   key= POST:token       value=token.add
 *   key= PUT:token/{}     value=token.modify
 *   key= DELETE:token/{}  value=token.delete
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public abstract class ACLFilter extends HttpFilter {

    private static final long serialVersionUID = 1L;
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACLFilter.class);
    private String defaultAcl;
    private Map<String, String> aclMap;
    private ACLChecker aclChecker;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String method;
        String path;
        String acl = defaultAcl;
        if(request instanceof HttpServletRequest req &&
                response instanceof HttpServletResponse resp) {
            method = req.getMethod();
            path = req.getPathInfo() != null ? req.getPathInfo().substring(1) : "";
            final String aclSearch = method + ":" + path;
            if (aclMap!=null) {
                String aclKey = aclMap.keySet().stream().
                        filter( key -> {
                            String keyRegex = key.replace("{}", "([^/]+)");
                            return aclSearch.matches(keyRegex);
                        } ).
                        sorted(Comparator.reverseOrder()).
                        findFirst().
                        orElse(null);
                if (aclKey != null) {
                    acl = aclMap.get(aclKey);
                }
            }
            try {
                logger.debug("ACLFilter: Checking {}", acl);
                ACLChecker checker = getACLChecker();
                checker.checkACL(req.getUserPrincipal(), method, path, acl);
                chain.doFilter(request, response);
            } catch (ForbiddenException fe) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                resp.setContentType(MimeType.APPLICATION_JSON);
                PrintWriter out = resp.getWriter();
                out.print(fe.getData().toJSON());
            }
        }
    }

    private CMSEngine getCMSEngine() {
        ServletContext servletContext = getServletContext();
        return (CMSEngine) servletContext.getAttribute("engine");
    }

    private synchronized ACLChecker getACLChecker() {
        if (aclChecker == null) {
            String context = getServletContext().getContextPath();
            String subsystem = context.startsWith("/") ? context.substring(1) : context;
            aclChecker = new ACLChecker(getCMSEngine(), subsystem);
        }
        return aclChecker;
    }

    public void setAcl(String acl) {
        this.defaultAcl = acl;
    }

    public void setAclMap(Map<String,String> acls) {
        this.aclMap = acls;
    }
}
