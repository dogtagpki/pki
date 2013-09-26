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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.net.URISyntaxException;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;


/**
 * @author alee
 *
 */
public class SystemConfigClient extends Client {

    private SystemConfigResource configClient;

    public SystemConfigClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "systemconfig");
        init();
    }

    public void init() throws URISyntaxException {
        configClient = createProxy(SystemConfigResource.class);
    }

    public ConfigurationResponse configure(ConfigurationRequest data) {
        return configClient.configure(data);
    }
}
