//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.HashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.common.ConfigData;
import org.dogtagpki.server.tps.config.ConfigDatabase;
import org.dogtagpki.server.tps.config.ConfigRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS configuration operations.
 * Replaces ConfigServlet.
 */
@Path("v2/config")
public class TPSConfigResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSConfigResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConfig() throws Exception {
        logger.debug("TPSConfigResource.getConfig()");
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
        return Response.ok(configData.toJSON()).build();
    }

    @PATCH
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConfig(String requestData) throws Exception {
        String method = "TPSConfigResource.updateConfig";
        Map<String, String> auditModParams = new HashMap<>();
        String userID = TPSEngineQuarkus.getUserID(identity);

        ConfigData configData = JSONSerializer.fromJSON(requestData, ConfigData.class);
        if (configData == null) {
            BadRequestException e = new BadRequestException("Config data is null.");
            auditModParams.put("Info", e.toString());
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, e.toString(), userID);
            throw e;
        }

        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            Map<String, String> newProperties = configData.getProperties();
            if (newProperties != null) {
                configDatabase.validateProperties(configRecord, null, newProperties);
                configDatabase.removeProperties(configRecord, null);
                configDatabase.addProperties(configRecord, null, newProperties);
            }

            configDatabase.commit();

            Map<String, String> properties = configDatabase.getProperties(configRecord, null);
            configData = new ConfigData();
            configData.setProperties(properties);
            engineQuarkus.auditConfigTokenGeneral(ILogger.SUCCESS, method, newProperties, null, userID);

        } catch (PKIException e) {
            logger.error(method + ": " + e.getMessage(), e);
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, e.toString(), userID);
            throw e;
        } catch (Exception e) {
            logger.error(method + ": " + e.getMessage(), e);
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, e.toString(), userID);
            throw new PKIException(e.getMessage());
        }
        return Response.ok(configData.toJSON()).build();
    }
}
