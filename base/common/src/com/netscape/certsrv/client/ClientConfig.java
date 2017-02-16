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
import java.net.URISyntaxException;
import java.net.URL;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

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

    String certDatabase;
    String tokenName;
    String certNickname;
    String certPassword;

    String username;
    String password;

    String messageFormat;

    public ClientConfig() {
    }

    public ClientConfig(ClientConfig config) {
        serverURL = config.serverURL;

        certDatabase = config.certDatabase;
        tokenName = config.tokenName;
        certNickname = config.certNickname;
        certPassword = config.certPassword;

        username = config.username;
        password = config.password;

        messageFormat = config.messageFormat;
    }

    @XmlElement(name="ServerURI")
    public URI getServerURI() {
        try {
            return serverURL.toURI();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public void setServerURI(String serverUri) throws URISyntaxException {
        try {
            this.serverURL = new URI(serverUri).toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
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

    @XmlElement(name="CertDatabase")
    public String getCertDatabase() {
        return certDatabase;
    }

    public void setCertDatabase(String certDatabase) {
        this.certDatabase = certDatabase;
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

    @XmlElement(name="CertPassword")
    public String getCertPassword() {
        return certPassword;
    }

    public void setCertPassword(String certPassword) {
        this.certPassword = certPassword;
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
        result = prime * result + ((certDatabase == null) ? 0 : certDatabase.hashCode());
        result = prime * result + ((certNickname == null) ? 0 : certNickname.hashCode());
        result = prime * result + ((certPassword == null) ? 0 : certPassword.hashCode());
        result = prime * result + ((messageFormat == null) ? 0 : messageFormat.hashCode());
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
        if (certDatabase == null) {
            if (other.certDatabase != null)
                return false;
        } else if (!certDatabase.equals(other.certDatabase))
            return false;
        if (certNickname == null) {
            if (other.certNickname != null)
                return false;
        } else if (!certNickname.equals(other.certNickname))
            return false;
        if (certPassword == null) {
            if (other.certPassword != null)
                return false;
        } else if (!certPassword.equals(other.certPassword))
            return false;
        if (messageFormat == null) {
            if (other.messageFormat != null)
                return false;
        } else if (!messageFormat.equals(other.messageFormat))
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
        before.setServerURI("http://localhost:8080");
        before.setCertDatabase("certs");
        before.setCertNickname("caadmin");
        before.setPassword("12345");

        String string = before.toString();
        System.out.println(string);

        ClientConfig after = ClientConfig.valueOf(string);
        System.out.println(before.equals(after));
    }
}
