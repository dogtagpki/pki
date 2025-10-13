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
package com.netscape.certsrv.system;

import jakarta.ws.rs.core.MultivaluedMap;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Ade Lee
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KRAConnectorInfo implements JSONSerializer {

    private static final String HOST = "host";
    private static final String PORT = "port";
    private static final String TRANSPORT_CERT= "transportCert";
    private static final String TRANSPORT_CERT_NICKNAME = "transportCertNickname";
    private static final String SUBSYSTEM_CERT= "subsystemCert";
    private static final String URI = "uri";
    private static final String TIMEOUT = "timeout";
    private static final String LOCAL = "local";
    private static final String ENABLE = "enable";

    String host;
    String port;
    String transportCert;
    String transportCertNickname;
    String subsystemCert;
    String uri;
    String timeout;
    String local;
    String enable;

    public KRAConnectorInfo() {
    }

    public KRAConnectorInfo(MultivaluedMap<String, String> form) {
        host = form.getFirst(HOST);
        port = form.getFirst(PORT);
        subsystemCert = form.getFirst(SUBSYSTEM_CERT);
        transportCert = form.getFirst(TRANSPORT_CERT);
        uri = form.getFirst(URI);
        timeout = form.getFirst(TIMEOUT);
        local = form.getFirst(LOCAL);
        enable = form.getFirst(ENABLE);
        transportCertNickname = form.getFirst(TRANSPORT_CERT_NICKNAME);
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getSubsystemCert() {
        return subsystemCert;
    }

    public void setSubsystemCert(String subsystemCert) {
        this.subsystemCert = subsystemCert;
    }

    public String getTransportCert() {
        return transportCert;
    }

    public void setTransportCert(String transportCert) {
        this.transportCert = transportCert;
    }

    public void setTransportCertNickname(String transportCertNickname) {
        this.transportCertNickname = transportCertNickname;
    }

    public String getTransportCertNickname() {
       return transportCertNickname;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getTimeout() {
        return timeout;
    }

    public void setTimeout(String timeout) {
        this.timeout = timeout;
    }

    public String getLocal() {
        return local;
    }

    public void setLocal(String local) {
        this.local = local;
    }

    public String getEnable() {
        return enable;
    }

    public void setEnable(String enable) {
        this.enable = enable;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((enable == null) ? 0 : enable.hashCode());
        result = prime * result + ((host == null) ? 0 : host.hashCode());
        result = prime * result + ((local == null) ? 0 : local.hashCode());
        result = prime * result + ((port == null) ? 0 : port.hashCode());
        result = prime * result + ((timeout == null) ? 0 : timeout.hashCode());
        result = prime * result + ((subsystemCert == null) ? 0 : subsystemCert.hashCode());
        result = prime * result + ((transportCert == null) ? 0 : transportCert.hashCode());
        result = prime * result + ((transportCertNickname == null) ? 0 : transportCertNickname.hashCode());
        result = prime * result + ((uri == null) ? 0 : uri.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KRAConnectorInfo other = (KRAConnectorInfo) obj;
        if (enable == null) {
            if (other.enable != null)
                return false;
        } else if (!enable.equals(other.enable))
            return false;
        if (host == null) {
            if (other.host != null)
                return false;
        } else if (!host.equals(other.host))
            return false;
        if (local == null) {
            if (other.local != null)
                return false;
        } else if (!local.equals(other.local))
            return false;
        if (port == null) {
            if (other.port != null)
                return false;
        } else if (!port.equals(other.port))
            return false;
        if (timeout == null) {
            if (other.timeout != null)
                return false;
        } else if (!timeout.equals(other.timeout))
            return false;
        if (subsystemCert == null) {
            if (other.subsystemCert != null)
                return false;
        } else if (!subsystemCert.equals(other.subsystemCert))
            return false;
        if (transportCert == null) {
            if (other.transportCert != null)
                return false;
        } else if (!transportCert.equals(other.transportCert))
            return false;
        if (transportCertNickname == null) {
            if (other.transportCertNickname != null)
                return false;
        } else if (!transportCertNickname.equals(other.transportCertNickname))
            return false;
        if (uri == null) {
            if (other.uri != null)
                return false;
        } else if (!uri.equals(other.uri))
            return false;
        return true;
    }

}
