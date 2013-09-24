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
package com.netscape.certsrv.client;

import java.net.URISyntaxException;
import java.util.LinkedHashMap;

/**
 * @author Endi S. Dewata
 */
public class Client {

    // server connection
    public PKIClient client;

    // subsystem name
    public String subsystem;

    // client name
    public String name;

    public LinkedHashMap<String, Client> clients = new LinkedHashMap<String, Client>();

    public Client(PKIClient client, String name) {
        // by default use the subsystem specified in server URI
        this(client, client.getSubsystem(), name);
    }

    public Client(PKIClient client, String subsystem, String name) {
        this.client = client;
        this.subsystem = subsystem;
        this.name = name;
    }

    public String getSubsystem() {
        return subsystem;
    }

    public String getName() {
        return name;
    }

    public void addClient(Client client) {
        clients.put(client.getName(), client);
    }

    public Client getClient(String name) {
        return clients.get(name);
    }

    public void removeClient(String name) {
        clients.remove(name);
    }

    public <T> T createProxy(Class<T> clazz) throws URISyntaxException {
        return client.createProxy(subsystem, clazz);
    }
}
