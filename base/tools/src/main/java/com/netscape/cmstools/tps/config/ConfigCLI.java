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

package com.netscape.cmstools.tps.config;

import java.io.IOException;
import java.util.Map;

import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.tps.config.ConfigClient;
import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.cmstools.tps.TPSCLI;

/**
 * @author Endi S. Dewata
 */
public class ConfigCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConfigCLI.class);

    public TPSCLI tpsCLI;
    public ConfigClient configClient;

    public ConfigCLI(TPSCLI tpsCLI) {
        super("config", "Configuration management commands", tpsCLI);
        this.tpsCLI = tpsCLI;

        addModule(new ConfigModifyCLI(this));
        addModule(new ConfigShowCLI(this));
    }

    public ConfigClient getConfigClient() throws Exception {

        if (configClient != null) return configClient;

        PKIClient client = getClient();
        configClient = (ConfigClient)parent.getClient("config");

        return configClient;
    }

    public static void printConfigData(ConfigData configData) throws IOException {

        if (configData.getStatus() != null) System.out.println("  Status: " + configData.getStatus());

        System.out.println("  Properties:");
        Map<String, String> properties = configData.getProperties();
        if (properties != null) {
            for (String name : properties.keySet()) {
                String value = properties.get(name);
                System.out.println("    " + name + ": " + value);
            }
        }

        Link link = configData.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
