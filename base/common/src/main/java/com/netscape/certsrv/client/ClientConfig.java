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

package com.netscape.certsrv.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ClientConfig implements JSONSerializer {

    URL serverURL;

    String nssDatabase;
    String nssPassword;

    Map<String, String> nssPasswords = new LinkedHashMap<>();

    String tokenName;
    String certNickname;

    String username;
    String password;

    String messageFormat;

    boolean certRevocationVerify;

    public ClientConfig() {
    }

    public ClientConfig(ClientConfig config) {
        serverURL = config.serverURL;

        nssDatabase = config.nssDatabase;
        nssPassword = config.nssPassword;

        nssPasswords.clear();
        nssPasswords.putAll(config.nssPasswords);

        tokenName = config.tokenName;
        certNickname = config.certNickname;

        username = config.username;
        password = config.password;

        messageFormat = config.messageFormat;

        certRevocationVerify = config.isCertRevocationVerify();

    }

    public void setServerURI(URI serverUri) {
        try {
            this.serverURL = serverUri.toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public URL getServerURL() {
        return serverURL;
    }

    public void setServerURL(String serverURL) throws MalformedURLException {
        this.serverURL = new URL(serverURL);
    }

    public void setServerURL(String protocol, String hostname, int port) throws MalformedURLException {
        this.serverURL = new URL(protocol, hostname, port, "");
    }

    public void setServerURL(URL serverURL) {
        this.serverURL = serverURL;
    }

    public String getSubsystem() {
        // path could be an empty string, "/", or "/<subsystem>"
        String path = serverURL.getPath();
        if (path.length() <= 1) return null;

        // return subsystem name
        return path.substring(1);
    }

    public String getNSSDatabase() {
        return nssDatabase;
    }

    public void setNSSDatabase(String nssDatabase) {
        this.nssDatabase = nssDatabase;
    }

    public String getNSSPassword() {
        return nssPassword;
    }

    public void setNSSPassword(String nssPassword) {
        this.nssPassword = nssPassword;
    }

    public Map<String, String> getNSSPasswords() {
        return nssPasswords;
    }

    public void setNSSPasswords(Map<String, String> nssPasswords) {
        this.nssPasswords.clear();
        this.nssPasswords.putAll(nssPasswords);
    }

    public String getNSSPassword(String name) {
        return nssPasswords.get(name);
    }

    public void setNSSPassword(String name, String value) {
        nssPasswords.put(name, value);
    }

    public String removeNSSPassword(String name) {
        return nssPasswords.remove(name);
    }

    public static class NSSPasswordList {
        public List<NSSPassword> passwords = new ArrayList<>();
    }

    public static class NSSPassword {

        public String name;

        public String value;
    }

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public String getCertNickname() {
        return certNickname;
    }

    public void setCertNickname(String certNickname) {
        this.certNickname = certNickname;
    }

    /**
     * @deprecated Use getNSSPassword() instead.
     */
    @Deprecated
    public String getCertPassword() {
        return nssPassword;
    }

    /**
     * @deprecated Use setNSSPassword() instead.
     */
    @Deprecated
    public void setCertPassword(String certPassword) {
        this.nssPassword = certPassword;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMessageFormat() {
        return messageFormat;
    }

    public void setMessageFormat(String messageFormat) {
        this.messageFormat = messageFormat;
    }


    public boolean isCertRevocationVerify() {
        return certRevocationVerify;
    }

    public void setCertRevocationVerify(boolean certRevocationVerify) {
        this.certRevocationVerify = certRevocationVerify;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certNickname == null) ? 0 : certNickname.hashCode());
        result = prime * result + ((messageFormat == null) ? 0 : messageFormat.hashCode());
        result = prime * result + ((nssDatabase == null) ? 0 : nssDatabase.hashCode());
        result = prime * result + ((nssPassword == null) ? 0 : nssPassword.hashCode());
        result = prime * result + ((nssPasswords == null) ? 0 : nssPasswords.hashCode());
        result = prime * result + ((password == null) ? 0 : password.hashCode());
        result = prime * result + ((serverURL == null) ? 0 : serverURL.hashCode());
        result = prime * result + ((tokenName == null) ? 0 : tokenName.hashCode());
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        result = result + (certRevocationVerify ? 0 : 1);
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
        ClientConfig other = (ClientConfig) obj;
        if (certNickname == null) {
            if (other.certNickname != null)
                return false;
        } else if (!certNickname.equals(other.certNickname))
            return false;
        if (messageFormat == null) {
            if (other.messageFormat != null)
                return false;
        } else if (!messageFormat.equals(other.messageFormat))
            return false;
        if (nssDatabase == null) {
            if (other.nssDatabase != null)
                return false;
        } else if (!nssDatabase.equals(other.nssDatabase))
            return false;
        if (nssPassword == null) {
            if (other.nssPassword != null)
                return false;
        } else if (!nssPassword.equals(other.nssPassword))
            return false;
        if (nssPasswords == null) {
            if (other.nssPasswords != null)
                return false;
        } else if (!nssPasswords.equals(other.nssPasswords))
            return false;
        if (password == null) {
            if (other.password != null)
                return false;
        } else if (!password.equals(other.password))
            return false;
        if (serverURL == null) {
            if (other.serverURL != null)
                return false;
        } else if (!serverURL.equals(other.serverURL))
            return false;
        if (tokenName == null) {
            if (other.tokenName != null)
                return false;
        } else if (!tokenName.equals(other.tokenName))
            return false;
        if (username == null) {
            if (other.username != null)
                return false;
        } else if (!username.equals(other.username))
            return false;
        if (certRevocationVerify != other.certRevocationVerify)
            return false;
        return true;
    }

}
