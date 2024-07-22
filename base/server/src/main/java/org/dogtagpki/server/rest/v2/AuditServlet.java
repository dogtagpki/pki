//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.File;
import java.io.PrintWriter;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.FileUtils;
import org.dogtagpki.server.rest.base.AuditServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class AuditServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(AuditServlet.class);

    private AuditServletBase auditServletBase;

    @Override
    public void init() throws ServletException {
        super.init();
        auditServletBase = new AuditServletBase(getEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getAuditConfig(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuditServlet.getAuditConfig(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        AuditConfig auditConfig = auditServletBase.createAuditConfig();
        out.println(auditConfig.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {""})
    public void updateAuditConfig(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuditServlet.updateAuditConfig(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        String requestData = request.getReader().lines().collect(Collectors.joining());
        AuditConfig auditConfig = JSONSerializer.fromJSON(requestData, AuditConfig.class);
        AuditConfig auditConfigNew = auditServletBase.updateAuditConfig(auditConfig, request.getUserPrincipal().getName());
        out.println(auditConfigNew.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void changeAuditStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuditServlet.changeAuditStatus(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        String action = request.getParameter("action");
        AuditConfig auditConfigNew = auditServletBase.changeAuditStatus(action, request.getUserPrincipal().getName());
        out.println(auditConfigNew.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"files"})
    public void findAuditFiles(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuditServlet.changeAuditStatus(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        AuditFileCollection auditConfigNew = auditServletBase.findAuditFiles();
        out.println(auditConfigNew.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"files/{}"})
    public void getAuditFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuditServlet.getAuditFile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String fileName = pathElement[1];
        File auditFile = auditServletBase.getAuditFile(fileName);
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        response.setContentLengthLong(auditFile.length());
        FileUtils.copyFile(auditFile, response.getOutputStream());
    }
}
