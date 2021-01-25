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

import java.io.StringReader;
import java.io.StringWriter;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Ade Lee
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KRAConnectorInfo {

    private static final String HOST = "host";
    private static final String PORT = "port";
    private static final String TRANSPORT_CERT= "transportCert";
    private static final String TRANSPORT_CERT_NICKNAME = "transportCertNickname";
    private static final String URI = "uri";
    private static final String TIMEOUT = "timeout";
    private static final String LOCAL = "local";
    private static final String ENABLE = "enable";

    @XmlElement
    String host;

    @XmlElement
    String port;

    @XmlElement
    String transportCert;

    @XmlElement
    String transportCertNickname;

    @XmlElement
    String uri;

    @XmlElement
    String timeout;

    @XmlElement
    String local;

    @XmlElement
    String enable;

    public KRAConnectorInfo() {
        // needed for jaxb
    }

    public KRAConnectorInfo(MultivaluedMap<String, String> form) {
        host = form.getFirst(HOST);
        port = form.getFirst(PORT);
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

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(KRAConnectorInfo.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static KRAConnectorInfo fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(KRAConnectorInfo.class).createUnmarshaller();
        return (KRAConnectorInfo) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws Exception {

        KRAConnectorInfo before = new KRAConnectorInfo();
        before.setEnable("true");
        before.setHost("host1.example.com");
        before.setLocal("false");
        before.setPort("8443");
        before.setTimeout("30");
        before.setUri("");
        before.setTransportCertNickname("KRA Transport Certificate");
        before.setTransportCert(
            "MIIDnDCCAoSgAwIBAgIBDzANBgkqhkiG9w0BAQsFADBGMSMwIQYDVQQKExpyZWRo" +
            "YXQuY29tIFNlY3VyaXR5IERvbWFpbjEfMB0GA1UEAxMWQ0EgU2lnbmluZyBDZXJ0" +
            "aWZpY2F0ZTAeFw0xMzAxMDkyMTE5MDBaFw0xNDEyMzAyMTE5MDBaMEkxIzAhBgNV" +
            "BAoTGnJlZGhhdC5jb20gU2VjdXJpdHkgRG9tYWluMSIwIAYDVQQDExlEUk0gVHJh" +
            "bnNwb3J0IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC" +
            "AQEAqayxDggWH9Cld0O/j+HDfv7cLQexYiaDq/sEcFPYkREGisaxZggiovqLfMkz" +
            "rSjutVtHuIEb3pU9frHYUjskbzdMbeU3nqDnA/ZPUw+YJe/6l19AbieADVB/L+6p" +
            "TkNMwS/xsQIRnalYW9R4rebw3WiwQFxVHIorGL9qxUS5d12uguJokH/CbIML9Pek" +
            "NgAZRGx87J4UkqTe5FImuEX8EwVWoW8Huc8QDthk1w5osz3jOTefwrJBEiI54d9F" +
            "hl4O8ckXfecCAPYfn0Mi54I1VAbSRZEiq6GJ/xrN1IwLkaG7EmXtLU2IkaMz62MJ" +
            "UmgBrlrtRj1eyAXLGwS4Fh4NVwIDAQABo4GRMIGOMB8GA1UdIwQYMBaAFMjscbmB" +
            "k0Gz2wVxGWkn9bjSA88wMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0" +
            "cDovL2FsZWUtd29ya3BjLnJlZGhhdC5jb206ODI4MC9jYS9vY3NwMA4GA1UdDwEB" +
            "/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEA" +
            "gCCPZ5+pkxZDgKJpisJ8/5TfKtN/q5pO8CNKIM9Cz78ucGEaR2lzJVH5EOdO2ZM6" +
            "y+5AhK2hcKifNI3DPAfYdYsSVBR6Mrij4/aAMZlqtKjlNs/LJ2TdKGRxxYsEAQL+" +
            "OToCfXijDh0kzQ9oSII+9fBCWljkq/K89bSGcwR/y1v+ll+z9Wci+QAFKUzmqZyL" +
            "eEbOOmYhgvVSnYV1XdB6lbWQOOdpytvECl1UaQUSsDfJkk8mH1Fkl0dnrChh7mXM" +
            "2ZBYwBsI2DhAyWBKQgQfgxQwxmobbg6BVnn9/CW7gJ0Gwb+VJEvRtaBOnjliP74/" +
            "Jb+fenCZE47zRNCDubBe+Q==");

        String xml = before.toXML();
        System.out.println("Before: " + xml);

        KRAConnectorInfo after = KRAConnectorInfo.fromXML(xml);
        System.out.println("After: " + after.toXML());

        System.out.println(before.equals(after));
    }
}
