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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.base;

import java.io.StringReader;
import java.io.StringWriter;

import javax.ws.rs.core.Response;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.databind.ObjectMapper;

public class PKIException extends RuntimeException {

    private static final long serialVersionUID = 6000910362260369923L;

    public int code;

    public PKIException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public PKIException(Response.Status status) {
        this(status, status.getReasonPhrase(), null);
    }

    public PKIException(String message) {
        this(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), message, null);
    }

    public PKIException(int code, String message) {
        this(code, message, null);
    }

    public PKIException(Response.Status status, String message) {
        this(status.getStatusCode(), message, null);
    }

    public PKIException(Throwable cause) {
        this(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), cause.getMessage(), cause);
    }

    public PKIException(String message, Throwable cause) {
        this(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), message, cause);
    }

    public PKIException(Response.Status status, String message, Throwable cause) {
        this(status.getStatusCode(), message, cause);
    }

    public PKIException(Data data) {
        this(data.code, data.message, null);
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public Data getData() {
        Data data = new Data();
        data.className = getClass().getName();
        data.code = code;
        data.message = getMessage();
        return data;
    }

    @XmlRootElement(name="PKIException")
    public static class Data extends ResourceMessage {

        @XmlElement(name="Code")
        public int code;

        @XmlElement(name="Message")
        public String message;

        public String toXML() throws Exception {
            JAXBContext context = JAXBContext.newInstance(Data.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            StringWriter out = new StringWriter();
            marshaller.marshal(this, out);
            return out.toString();
        }

        public static Data fromXML(String string) throws Exception {
            JAXBContext context = JAXBContext.newInstance(Data.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return (Data) unmarshaller.unmarshal(new StringReader(string));
        }

        public String toJSON() throws Exception {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(this);
        }

        public static Data fromJSON(String json) throws Exception {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, Data.class);
        }
    }

    public static void main(String args[]) throws Exception {
        Data data = new Data();
        data.className = PKIException.class.getName();
        data.code = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
        data.message = "An error has occured";
        data.setAttribute("attr1", "value1");
        data.setAttribute("attr2", "value2");

        JAXBContext context = JAXBContext.newInstance(Data.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(data, System.out);
    }
}
