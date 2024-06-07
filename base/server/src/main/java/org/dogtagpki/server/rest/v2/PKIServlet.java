//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Locale;

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

    public abstract void get(HttpServletRequest request, HttpServletResponse response) throws Exception;

    public abstract void post(HttpServletRequest request, HttpServletResponse response) throws Exception;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json");
        try {
            setSessionContext(request);
            get(request, response);
        } catch (ResourceNotFoundException re) {
            try {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                PrintWriter out = response.getWriter();
                out.print(re.getData().toJSON());
            } catch(Exception ex) {
                logger.error(ERROR_RESPONSE, ex.getMessage(), ex);
            }
        } catch (BadRequestException bre) {
            try {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                PrintWriter out = response.getWriter();
                out.print(bre.getData().toJSON());
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

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json");
        try {
            setSessionContext(request);
            post(request, response);
        } catch (ResourceNotFoundException re) {
            try {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, re.getData().toJSON());
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
