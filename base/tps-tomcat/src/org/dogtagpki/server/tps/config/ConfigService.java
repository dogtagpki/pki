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
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.certsrv.tps.config.ConfigResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ConfigService extends PKIService implements ConfigResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

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
    public ConfigData getConfig() {

        CMS.debug("ConfigService.getConfig()");

        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            Map<String, String> properties = configDatabase.getProperties(configRecord, null);
            return createConfigData(properties);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConfig(ConfigData configData) {

        if (configData == null) throw new BadRequestException("Config data is null.");

        CMS.debug("ConfigService.updateConfig()");

        try {
            ConfigDatabase configDatabase = new ConfigDatabase();
            ConfigRecord configRecord = configDatabase.getRecord("Generals");

            // validate new properties
            Map<String, String> properties = configData.getProperties();
            configDatabase.validateProperties(configRecord, null, properties);

            // remove old properties
            configDatabase.removeProperties(configRecord, null);

            // add new properties
            configDatabase.addProperties(configRecord, null, properties);

            configDatabase.commit();

            properties = configDatabase.getProperties(configRecord, null);
            configData = createConfigData(properties);

            return Response
                    .ok(configData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
