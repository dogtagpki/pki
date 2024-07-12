//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Principal;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;

/**
 * Implement the basic class to handle REST APIs
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public abstract class PKIServlet extends HttpServlet {
    public static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(PKIServlet.class);
    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_SIZE = 20;
    public static final int MIN_FILTER_LENGTH = 3;
    private static final String ERROR_RESPONSE= "PKIServlet - error processing request: {}";

    private enum HttpMethod {
        GET, POST, PATCH, PUT, DELETE
    }

    public abstract void get(HttpServletRequest request, HttpServletResponse response) throws Exception;

    public abstract void post(HttpServletRequest request, HttpServletResponse response) throws Exception;

    public abstract void put(HttpServletRequest request, HttpServletResponse response) throws Exception;

    public abstract void patch(HttpServletRequest request, HttpServletResponse response) throws Exception;

    public abstract void delete(HttpServletRequest request, HttpServletResponse response) throws Exception;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doOperation(HttpMethod.GET, request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doOperation(HttpMethod.POST, request, response);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doOperation(HttpMethod.PUT, request, response);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doOperation(HttpMethod.DELETE, request, response);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String method = req.getMethod();
        if (!method.equals("PATCH")) {
            super.service(req, res);
            return;
        }
        this.doOperation(HttpMethod.PATCH, req, res);
    }

    private void doOperation(HttpMethod method, HttpServletRequest request, HttpServletResponse response) {
        response.setContentType("application/json");
        try {
            setSessionContext(request);
            switch (method) {
                case PUT:
                    put(request, response);
                    break;
                case PATCH:
                    patch(request, response);
                    break;
                case DELETE:
                    delete(request, response);
                    break;
                case POST:
                    post(request, response);
                    break;
                case GET:
                default:
                    get(request, response);
            }
        } catch (ResourceNotFoundException re) {
            try {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                PrintWriter out = response.getWriter();
                out.print(re.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        }catch (BadRequestException bre) {
            try {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                PrintWriter out = response.getWriter();
                out.print(bre.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (BadRequestDataException bre) {
            try {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, bre.getMessage());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (UnauthorizedException ue) {
            try {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                PrintWriter out = response.getWriter();
                out.print(ue.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (ForbiddenException ue) {
            try {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                PrintWriter out = response.getWriter();
                out.print(ue.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (PKIException bre) {
            try {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                PrintWriter out = response.getWriter();
                out.print(bre.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        }
    }
    protected abstract String getSubsystemName();

    protected String getSubsystemConfDir() {
        return CMS.getInstanceDir() + File.separator + getSubsystemName() + File.separator + "conf";
    }

    protected String getSharedSubsystemConfDir() {
        return File.separator + "usr" + File.separator + "share" + File.separator + "pki" +
                File.separator + getSubsystemName() + File.separator + "conf";
    }

    protected ResourceBundle getResourceBundle(String name, Locale locale) throws MalformedURLException {

        // Look in <instance>/<subsystem>/conf first,
        // then fallback to /usr/share/pki/<subsystem>/conf.
        URL[] urls = {
                new File(getSubsystemConfDir()).toURI().toURL(),
                new File(getSharedSubsystemConfDir()).toURI().toURL()
        };

        ClassLoader loader = new URLClassLoader(urls);
        return ResourceBundle.getBundle(name, locale, loader);
    }

    private void setSessionContext(HttpServletRequest request) {
        logger.debug("PKIServlet.setSessionContex: {}", request.getRequestURI());

        Principal principal = request.getUserPrincipal();
        // If unauthenticated, ignore.
        if (principal == null) {
            logger.debug("PKIServlet.setSessionContex: Not authenticated.");
            SessionContext.releaseContext();
            return;
        }

        logger.debug("PKIServlet.setSessionContex: principal: {}", principal.getName());

        AuthToken authToken = null;

        if (principal instanceof PKIPrincipal pr)
            authToken = pr.getAuthToken();
        else if (principal instanceof GenericPrincipal pr)
            authToken = new ExternalAuthToken(pr);

        // If missing auth token, reject request.
        if (authToken == null) {
            logger.warn("PKIServlet.setSessionContex: No authorization token present.");
            throw new ForbiddenException("No authorization token present.");
        }

        SessionContext context = SessionContext.getContext();

        String ip = request.getRemoteAddr();
        context.put(SessionContext.IPADDRESS, ip);

        Locale locale = request.getLocale();
        context.put(SessionContext.LOCALE, locale);

        context.put(SessionContext.AUTH_TOKEN, authToken);
        context.put(SessionContext.USER_ID, principal.getName());
        if (principal instanceof PKIPrincipal pr)
            context.put(SessionContext.USER, pr.getUser());
    }
}
