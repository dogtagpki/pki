//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Principal;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.MediaType;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.WebAction;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * Implement the basic class to handle REST APIs
 *
 * API are routed to method in subclasses implementing specific actions annotated with WebAction
 *
 * @see WebAction
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public abstract class PKIServlet extends HttpServlet {
    public static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(PKIServlet.class);
    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_SIZE = 20;
    public static final int MIN_FILTER_LENGTH = 3;
    private static final String ERROR_RESPONSE= "PKIServlet - error processing request: {}";
    public static final int DEFAULT_LONG_CACHE_LIFETIME = 1000;

    public enum HttpMethod {
        GET, POST, PATCH, PUT, DELETE
    }

    protected Map<String, Method> webActions;


    @Override
    public void init() throws ServletException {
        super.init();
        webActions = new HashMap<>();

        for (Method method : this.getClass().getMethods()) {
            WebAction wActions = method.getAnnotation(WebAction.class);
            if (wActions == null)
                continue;
            HttpMethod met = wActions.method();
            String[] paths = wActions.paths();
            for (String path: paths) {
                logger.debug("PKIServlet: class {} handle: {}:{}", this.getClass(), met, path);
                webActions.put(met.toString() + ":" + path, method);
            }
        }
    }

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
        response.setContentType(MediaType.APPLICATION_JSON);
        try {
            setSessionContext(request);
            Method actionMethod = getActionMethod(method, request.getPathInfo());
            if (actionMethod == null) {
                String allowMethods = getAllowedMethods(request.getPathInfo());
                if (allowMethods == null) {
                        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                } else {
                        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                        response.setHeader("Allow: ", allowMethods);
                }
                return;
            }
            actionMethod.invoke(this, request, response);
        } catch (InvocationTargetException ite) {
            try {
                if (ite.getCause() instanceof PKIException pkie) {
                    response.setStatus(pkie.getCode());
                    PrintWriter out = response.getWriter();
                    out.print(pkie.getData().toJSON());
                } else {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ite.getCause().getMessage());
                }
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

    public Method getActionMethod(HttpMethod met, String path) {
        final String reqMethod;
        if (path == null) {
            reqMethod = met.toString() + ":";
        } else {
            reqMethod = met.toString() + ":" + (path.startsWith("/") ? path.substring(1) : path);
        }
        String keyPath = webActions.keySet().stream().
                filter( key -> {
                    String keyRegex = key.replace("{}", "([^/]+)");
                    return reqMethod.matches(keyRegex);
                    } ).
                sorted(Comparator.naturalOrder()).
                findFirst().
                orElse(null);
        return keyPath == null ? null : webActions.get(keyPath);
    }

    public String getAllowedMethods(String path) {
        final String matchingPath;
        if (path == null) {
            matchingPath = "";
        } else {
            matchingPath = path.startsWith("/") ? path.substring(1) : path;
        }
        List<String> keyPaths = webActions.keySet().stream().
                filter( key -> {
                    String keyRegex = key.substring(key.indexOf(":") + 1);
                    keyRegex = keyRegex.replace("{}", "([^/]+)");
                    return matchingPath.matches(keyRegex);
                    }).
                collect(Collectors.toList());
        if (keyPaths == null || keyPaths.isEmpty()) {
            return null;
        }
        StringBuilder methods = new StringBuilder();
        for (String k: keyPaths) {
            if (methods.indexOf(k) == -1) {
                methods.append(k.substring(0, k.indexOf(":"))).append(", ");
            }
        }
        return methods.substring(0, methods.lastIndexOf(","));
    }

    protected String getSubsystemName() {
        return getEngine().getID();
    }

    protected CMSEngine getEngine() {
        ServletContext servletContext = getServletContext();
        return (CMSEngine) servletContext.getAttribute("engine");
    }

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
