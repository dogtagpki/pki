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

import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIModule;

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

    @Override
    public String getName() {
        return module.getName();
    }

    @Override
    public void setName(String name) {
        module.setName(name);
    }

    @Override
    public String getFullName() {
        return module.getFullName();
    }

    @Override
    public String getFullModuleName(String moduleName) {
        return module.getFullModuleName(moduleName);
    }

    @Override
    public String getDescription() {
        return module.getDescription();
    }

    @Override
    public void setDescription(String description) {
        module.setDescription(description);
    }

    @Override
    public CLI getParent() {
        return module.getParent();
    }

    @Override
    public Collection<CLIModule> getModules() {
        return module.getModules();
    }

    @Override
    public CLIModule getModule(String name) {
        return module.getModule(name);
    }

    @Override
    public void addModule(CLI module) {
        this.module.addModule(module);
    }

    @Override
    public CLIModule removeModule(String name) {
        return module.removeModule(name);
    }

    @Override
    public PKIClient getClient() throws Exception {
        return module.getClient();
    }

    @Override
    public Object getClient(String name) throws Exception {
        return module.getClient(name);
    }

    @Override
    public void printHelp() throws Exception {
        module.printHelp();
    }

    @Override
    public void execute(String[] args) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AccountClient accountClient = null;

        try {
            // login if username or nickname is specified
            ClientConfig config = module.getConfig();
            if (config.getUsername() != null || config.getCertNickname() != null) {

                String subsystem = config.getSubsystem();
                if (subsystem == null) subsystem = defaultSubsystem;

                PKIClient client = module.getClient();
                accountClient = new AccountClient(client, subsystem);
                accountClient.login();
            }

            module.execute(args);

        } finally {
            if (accountClient != null) accountClient.logout();
        }
    }
}
