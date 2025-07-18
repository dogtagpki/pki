//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.common.ConfigData;
import org.dogtagpki.server.tps.config.ConfigDatabase;
import org.dogtagpki.server.tps.config.ConfigRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.util.JSONSerializer;

@WebServlet(
        name = "tpsConfig",
        urlPatterns = "/v2/config/*")
public class ConfigServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(ConfigServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getConfig(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConfigServlet.getConfig(): session: {}", session.getId());
        ConfigData configData = new ConfigData();
        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            Map<String, String> properties = configDatabase.getProperties(configRecord, null);

            configData.setProperties(properties);
        } catch (PKIException e) {
            throw e;
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
        PrintWriter out = response.getWriter();
        out.println(configData.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {""})
    public void updateConfig(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "ConfigServlet.updateConfig";
        Map<String, String> auditModParams = new HashMap<>();

        HttpSession session = request.getSession();
        logger.debug("ConfigServlet.updateConfig(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ConfigData configData = JSONSerializer.fromJSON(requestData, ConfigData.class);
        if (configData == null) {
            BadRequestException e = new BadRequestException("Config data is null.");
            auditModParams.put("Info", e.toString());
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, e.toString());
            throw e;
        }
        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            Map<String, String> newProperties = configData.getProperties();
            if (newProperties != null) {
                // validate new properties
                configDatabase.validateProperties(configRecord, null, newProperties);

                // remove old properties
                configDatabase.removeProperties(configRecord, null);

                // add new properties
                configDatabase.addProperties(configRecord, null, newProperties);
            }

            configDatabase.commit();

            Map<String, String> properties = configDatabase.getProperties(configRecord, null);
            configData =  new ConfigData();
            configData.setProperties(properties);
            auditConfigTokenGeneral(ILogger.SUCCESS, method,
                    newProperties, null);
        } catch (PKIException e) {
            logger.error(method +": " + e.getMessage(), e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error(method +": " + e.getMessage(), e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw new PKIException(e.getMessage());
        }
        PrintWriter out = response.getWriter();
        out.println(configData.toJSON());
    }

}
