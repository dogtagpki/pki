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

package com.netscape.cmstools.cli;

import java.util.Collection;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;


/**
 * This class provides a mechanism to authenticate against
 * the appropriate subsystem for the CLI command.
 *
 * @author Endi S. Dewata
 */
public class ProxyCLI extends CLI {

    CLI module;
    String defaultSubsystem;

    public ProxyCLI(CLI module, String defaultSubsystem) {
        super(module.getName(), module.getDescription(), module.getParent());

        this.module = module;
        this.defaultSubsystem = defaultSubsystem;
    }

    public String getName() {
        return module.getName();
    }

    public void setName(String name) {
        module.setName(name);
    }

    public String getFullName() {
        return module.getFullName();
    }

    public String getFullModuleName(String moduleName) {
        return module.getFullModuleName(moduleName);
    }

    public String getDescription() {
        return module.getDescription();
    }

    public void setDescription(String description) {
        module.setDescription(description);
    }

    public CLI getParent() {
        return module.getParent();
    }

    public Collection<CLI> getModules() {
        return module.getModules();
    }

    public CLI getModule(String name) {
        return module.getModule(name);
    }

    public void addModule(CLI module) {
        this.module.addModule(module);
    }

    public CLI removeModule(String name) {
        return module.removeModule(name);
    }

    public PKIClient getClient() {
        return module.getClient();
    }

    public Object getClient(String name) {
        return module.getClient(name);
    }

    public void printHelp() {
        module.printHelp();
    }

    public void execute(String[] args) throws Exception {

        PKIClient client = module.getParent().getClient();
        AccountClient accountClient = null;

        try {
            // login if username or nickname is specified
            ClientConfig config = client.getConfig();
            if (config.getUsername() != null || config.getCertNickname() != null) {

                String subsystem = config.getSubsystem();
                if (subsystem == null) subsystem = defaultSubsystem;

                accountClient = new AccountClient(client, subsystem);
                accountClient.login();
            }

            module.execute(args);

        } finally {
            if (accountClient != null) accountClient.logout();
        }
    }
}
