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

import java.io.ByteArrayOutputStream;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
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

    public String toString() {
        try {
            JAXBContext context = JAXBContext.newInstance(KRAConnectorInfo.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            marshaller.marshal(this, stream);
            return stream.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String args[]) throws Exception {
        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setEnable("true");
        info.setHost("host1.example.com");
        info.setLocal("false");
        info.setPort("8443");
        info.setTimeout("30");
        info.setUri("");
        info.setTransportCert(
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

        System.out.println(info);
    }
}

