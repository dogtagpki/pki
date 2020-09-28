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

import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Client")
public class ClientConfig {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(ClientConfig.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(ClientConfig.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    URL serverURL;

    String nssDatabase;
    String nssPassword;

    Map<String, String> nssPasswords = new LinkedHashMap<String, String>();

    String tokenName;
    String certNickname;

    String username;
    String password;

    String messageFormat;

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
    }

    public void setServerURI(URI serverUri) {
        try {
            this.serverURL = serverUri.toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    @XmlElement(name="ServerURL")
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

    @XmlElement(name="NSSDatabase")
    public String getNSSDatabase() {
        return nssDatabase;
    }

    public void setNSSDatabase(String nssDatabase) {
        this.nssDatabase = nssDatabase;
    }

    @XmlElement(name="NSSPassword")
    public String getNSSPassword() {
        return nssPassword;
    }

    public void setNSSPassword(String nssPassword) {
        this.nssPassword = nssPassword;
    }

    @XmlElement(name = "NSSPasswords")
    @XmlJavaTypeAdapter(NSSPasswordsAdapter.class)
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

    public static class NSSPasswordsAdapter extends XmlAdapter<NSSPasswordList, Map<String, String>> {

        public NSSPasswordList marshal(Map<String, String> map) {
            NSSPasswordList list = new NSSPasswordList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                NSSPassword password = new NSSPassword();
                password.name = entry.getKey();
                password.value = entry.getValue();
                list.passwords.add(password);
            }
            return list;
        }

        public Map<String, String> unmarshal(NSSPasswordList list) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            for (NSSPassword password : list.passwords) {
                map.put(password.name, password.value);
            }
            return map;
        }
    }

    public static class NSSPasswordList {
        @XmlElement(name = "NSSPassword")
        public List<NSSPassword> passwords = new ArrayList<NSSPassword>();
    }

    public static class NSSPassword {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
    }

    @XmlElement(name="Token")
    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    @XmlElement(name="CertNickname")
    public String getCertNickname() {
        return certNickname;
    }

    public void setCertNickname(String certNickname) {
        this.certNickname = certNickname;
    }

    /**
     * @deprecated Use getNSSPassword() instead.
     */
    @XmlElement(name="CertPassword")
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

    @XmlElement(name="Username")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @XmlElement(name="Password")
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @XmlElement(name="MessageFormat")
    public String getMessageFormat() {
        return messageFormat;
    }

    public void setMessageFormat(String messageFormat) {
        this.messageFormat = messageFormat;
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
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static ClientConfig valueOf(String string) throws Exception {
        try {
            return (ClientConfig)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        ClientConfig before = new ClientConfig();
        before.setServerURL("http://localhost:8080");

        before.setNSSDatabase("certs");
        before.setNSSPassword("12345");
        before.setNSSPassword("internal", "12345");
        before.setNSSPassword("hsm", "12345");

        before.setCertNickname("caadmin");

        before.setUsername("caadmin");
        before.setPassword("12345");

        String string = before.toString();
        System.out.println(string);

        ClientConfig after = ClientConfig.valueOf(string);
        System.out.println(before.equals(after));
    }
}
