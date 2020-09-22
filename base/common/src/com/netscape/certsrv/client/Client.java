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

import java.util.LinkedHashMap;

import javax.ws.rs.core.Response;

/**
 * @author Endi S. Dewata
 */
public class Client {

    // server connection
    public PKIClient client;

    // subsystem name
    public String subsystem;

    // API prefix
    public String prefix;

    // client name
    public String name;

    public LinkedHashMap<String, Client> clients = new LinkedHashMap<String, Client>();

    public Client(PKIClient client, String subsystem, String name) {
        this(client, subsystem, "rest", name);
    }

    public Client(PKIClient client, String subsystem, String prefix, String name) {
        this.client = client;
        this.subsystem = subsystem;
        this.prefix = prefix;
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

    public <T> T createProxy(Class<T> clazz) throws Exception {

        String path = "/" + subsystem;

        if (prefix != null) {
            path += "/" + prefix;
        }

        return client.createProxy(path, clazz);
    }

    public Response get() throws Exception {
        return get((String) null);
    }

    public <T> T get(Class<T> responseType) throws Exception {
        return get((String) null, responseType);
    }

    public Response get(String suffix) throws Exception {
        String path = "/" + subsystem;

        if (prefix != null) {
            path += "/" + prefix;
        }

        if (name != null) {
            path += "/" + name;
        }

        if (suffix != null) {
            path += "/" + suffix;
        }

        return client.get(path);
    }

    public <T> T get(String suffix, Class<T> responseType) throws Exception {
        String path = "/" + subsystem;

        if (prefix != null) {
            path += "/" + prefix;
        }

        if (name != null) {
            path += "/" + name;
        }

        if (suffix != null) {
            path += "/" + suffix;
        }

        return client.get(path, responseType);
    }

    public Response post() throws Exception {
        return post((String) null);
    }

    public <T> T post(Class<T> responseType) throws Exception {
        return post((String) null, responseType);
    }

    public Response post(String suffix) throws Exception {
        String path = "/" + subsystem;

        if (prefix != null) {
            path += "/" + prefix;
        }

        if (name != null) {
            path += "/" + name;
        }

        if (suffix != null) {
            path += "/" + suffix;
        }

        return client.post(path);
    }

    public <T> T post(String suffix, Class<T> responseType) throws Exception {
        String path = "/" + subsystem;

        if (prefix != null) {
            path += "/" + prefix;
        }

        if (name != null) {
            path += "/" + name;
        }

        if (suffix != null) {
            path += "/" + suffix;
        }

        return client.post(path, responseType);
    }
}
