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
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.tps.config.ConfigCollection;
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

    public Collection<String> getPatterns(String configID, Map<String, String> map) {
        Collection<String> patterns = new ArrayList<String>();

        String pattern = map.get("target." + configID + ".pattern");
        if (pattern != null) {
            // replace \| with |
            pattern = pattern.replace("\\|",  "|");

            String list = map.get("target." + configID + ".list");
            if (list == null) {
                patterns.add(pattern);

            } else {
                for (String value : list.split(",")) {
                    patterns.add(pattern.replace("$name", value));
                }
            }
        }

        return patterns;
    }

    public ConfigData createConfigData(String configID, Map<String, String> map) throws UnsupportedEncodingException {

        String displayName = map.get("target." + configID + ".displayname");
        if (displayName == null) {
            throw new ResourceNotFoundException("Configuration " + configID + " not found.");
        }

        ConfigData configData = new ConfigData();
        configData.setID(configID);
        configData.setDisplayName(displayName);

        // add properties that fit the patterns
        Collection<String> patterns = getPatterns(configID, map);
        for (String pattern : patterns) {
            for (String name : map.keySet()) {
                if (!name.matches(pattern)) continue;

                String value = map.get(name);
                configData.setProperty(name, value);
            }
        }

        configID = URLEncoder.encode(configID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ConfigResource.class).path("{configID}").build(configID);
        configData.setLink(new Link("self", uri));

        return configData;
    }

    @Override
    public ConfigCollection findConfigs() {

        CMS.debug("ConfigService.findConfigs()");

        try {
            IConfigStore configStore = CMS.getConfigStore();
            Map<String, String> map = configStore.getProperties();

            ConfigCollection result = new ConfigCollection();

            Collection<String> configIDs = new LinkedHashSet<String>();
            configIDs.add("Generals");

            String list = map.get("target.configure.list");
            if (list != null) {
                configIDs.addAll(Arrays.asList(list.split(",")));
            }

            list = map.get("target.agent_approve.list");
            if (list != null) {
                configIDs.addAll(Arrays.asList(list.split(",")));
            }

            for (String configID : configIDs) {
                ConfigData configData = createConfigData(configID, map);
                result.addConfig(configData);
            }

            return result;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public ConfigData getConfig(String configID) {

        CMS.debug("ConfigService.getConfig()");

        try {
            IConfigStore configStore = CMS.getConfigStore();
            Map<String, String> map = configStore.getProperties();

            return createConfigData(configID, map);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConfig(String configID, ConfigData newConfigData) {

        CMS.debug("ConfigService.updateConfig()");

        try {
            IConfigStore configStore = CMS.getConfigStore();
            Map<String, String> map = configStore.getProperties();

            // verify that new properties fit the patterns
            Collection<String> patterns = getPatterns(configID, map);
            for (String pattern : patterns) {
                for (String name : newConfigData.getPropertyNames()) {
                    if (name.matches(pattern)) continue;
                    throw new BadRequestException("Invalid property: " + name);
                }
            }

            // remove old properties
            ConfigData configData = createConfigData(configID, map);
            for (String name : configData.getPropertyNames()) {
                configStore.remove(name);
            }

            // store new properties
            for (String name : newConfigData.getPropertyNames()) {
                String value = newConfigData.getProperty(name);
                configStore.put(name, value);
            }

            configStore.commit(true);

            newConfigData = getConfig(configID);

            return Response
                    .ok(newConfigData)
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
