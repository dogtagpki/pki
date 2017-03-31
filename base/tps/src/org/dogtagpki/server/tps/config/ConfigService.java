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

package org.dogtagpki.server.tps.config;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.certsrv.tps.config.ConfigResource;
import com.netscape.cms.servlet.base.SubsystemService;

/**
 * @author Endi S. Dewata
 */
public class ConfigService extends SubsystemService implements ConfigResource {

    public ConfigService() {
        CMS.debug("ConfigService.<init>()");
    }

    public ConfigData createConfigData(Map<String, String> properties) throws UnsupportedEncodingException {

        ConfigData configData = new ConfigData();
        configData.setProperties(properties);

        URI uri = uriInfo.getBaseUriBuilder().path(ConfigResource.class).build();
        configData.setLink(new Link("self", uri));

        return configData;
    }

    @Override
    public Response getConfig() {

        CMS.debug("ConfigService.getConfig()");

        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            Map<String, String> properties = configDatabase.getProperties(configRecord, null);

            return createOKResponse(createConfigData(properties));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConfig(ConfigData configData) {
        String method = "ConfigService.updateConfig";
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (configData == null) {
            BadRequestException e = new BadRequestException("Config data is null.");
            auditModParams.put("Info", e.toString());
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, e.toString());
            throw e;
        }

        CMS.debug("ConfigService.updateConfig()");

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
            configData = createConfigData(properties);

            auditConfigTokenGeneral(ILogger.SUCCESS, method,
                    newProperties, null);

            return createOKResponse(configData);

        } catch (PKIException e) {
            CMS.debug(method +": " + e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug(method +": " + e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw new PKIException(e.getMessage());
        }
    }
}
