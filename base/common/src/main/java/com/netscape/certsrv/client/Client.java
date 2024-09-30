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
import java.util.Map;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;

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

    public LinkedHashMap<String, Client> clients = new LinkedHashMap<>();

    public Client(PKIClient client, String subsystem, String name) {
        this(client, subsystem, client.getAPIVersion(), name);
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

    public String getTargetPath(String suffix) {

        StringBuilder sb = new StringBuilder(subsystem);

        if (prefix != null) {
            sb.append("/").append(prefix);
        }

        if (name != null) {
            sb.append("/").append(name);
        }

        if (suffix != null) {
            sb.append("/").append(suffix);
        }

        return sb.toString();
    }

    public WebTarget target(String suffix, Map<String, Object> params) {
        String path = getTargetPath(suffix);
        return client.target(path, params);
    }

    public <T> T get(Class<T> responseType) throws Exception {
        return get((String) null, responseType);
    }

    public <T> T get(String suffix, Class<T> responseType) throws Exception {
        return get(suffix, null, responseType);
    }

    public <T> T get(String suffix, Map<String, Object> params, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.get(path, params, responseType);
    }

    public <T> T get(String suffix, Map<String, Object> params, GenericType<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.get(path, params, responseType);
    }

    public <T> T post(Class<T> responseType) throws Exception {
        return post((String) null, responseType);
    }

    public <T> T post(String suffix, Class<T> responseType) throws Exception {
        return post(suffix, null, responseType);
    }

    public <T> T post(String suffix, Map<String, Object> params, Class<T> responseType) throws Exception {
        return post(suffix, params, null, responseType);
    }

    public <T> T post(String suffix, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.post(path, params, entity, responseType);
    }

    public <T> T put(String suffix, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.put(path, params, entity, responseType);
    }

    public <T> T patch(String suffix, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.patch(path, params, entity, responseType);
    }

    public <T> T delete(String suffix, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.delete(path, responseType);
    }

    public <T> T delete(String suffix, Map<String, Object> params, Class<T> responseType) throws Exception {
        String path = getTargetPath(suffix);
        return client.delete(path, params, responseType);
    }
}
