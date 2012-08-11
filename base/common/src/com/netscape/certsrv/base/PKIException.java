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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

public class PKIException extends RuntimeException {

    private static final long serialVersionUID = 6000910362260369923L;

    public int code;

    public PKIException(String message) {
        super(message);
        code = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    public PKIException(int code, String message) {
        super(message);
        this.code = code;
    }

    public PKIException(Response.Status status, String message) {
        super(message);
        code = status.getStatusCode();
    }

    public PKIException(String message, Throwable cause) {
        super(message, cause);
        code = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    public PKIException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public PKIException(Response.Status status, String message, Throwable cause) {
        super(message, cause);
        code = status.getStatusCode();
    }

    public PKIException(Data data) {
        super(data.message);
        code = data.code;
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
    public static class Data {

        @XmlElement(name="ClassName")
        public String className;

        @XmlElement(name="Code")
        public int code;

        @XmlElement(name="Message")
        public String message;

        @XmlElement(name="Attributes")
        @XmlJavaTypeAdapter(MapAdapter.class)
        public Map<String, String> attributes = new LinkedHashMap<String, String>();

        public String getAttribute(String name) {
            return attributes.get(name);
        }

        public void setAttribute(String name, String value) {
            attributes.put(name, value);
        }
    }

    public static class MapAdapter extends XmlAdapter<AttributeList, Map<String, String>> {

        public AttributeList marshal(Map<String, String> map) {
            AttributeList list = new AttributeList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                Attribute attribute = new Attribute();
                attribute.name = entry.getKey();
                attribute.value = entry.getValue();
                list.attributes.add(attribute);
            }
            return list;
        }

        public Map<String, String> unmarshal(AttributeList list) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            for (Attribute attribute : list.attributes) {
                map.put(attribute.name, attribute.value);
            }
            return map;
        }
    }

    public static class AttributeList {
        @XmlElement(name="Attribute")
        public List<Attribute> attributes = new ArrayList<Attribute>();
    }

    public static class Attribute {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
    }

    @Provider
    public static class Mapper implements ExceptionMapper<PKIException> {

        public Response toResponse(PKIException exception) {
            // convert PKIException into HTTP response with XML content
            return Response
                    .status(exception.getCode())
                    .entity(exception.getData())
                    .type(MediaType.APPLICATION_XML)
                    .build();
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
