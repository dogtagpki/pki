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

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.http.HttpStatus;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

public class PKIException extends RuntimeException {

    private static final long serialVersionUID = 6000910362260369923L;

    private int code;

    public PKIException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public PKIException(String message) {
        this(HttpStatus.SC_INTERNAL_SERVER_ERROR, message, null);
    }

    public PKIException(int code, String message) {
        this(code, message, null);
    }

    public PKIException(Throwable cause) {
        this(HttpStatus.SC_INTERNAL_SERVER_ERROR, cause.getMessage(), cause);
    }

    public PKIException(String message, Throwable cause) {
        this(HttpStatus.SC_INTERNAL_SERVER_ERROR, message, cause);
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

    @JsonInclude(Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown=true)
    @JsonSerialize(using=PKIExceptionSerializer.class)
    @JsonDeserialize(using=PKIExceptionDeserializer.class)
    public static class Data extends RESTMessage {

        public int code;
        public String message;

        @Override
        public Element toDOM(Document document) {

            Element element = document.createElement("PKIException");

            toDOM(document, element);

            Element codeElement = document.createElement("Code");
            codeElement.appendChild(document.createTextNode(Integer.toString(code)));
            element.appendChild(codeElement);

            if (message != null) {
                Element messageElement = document.createElement("Message");
                messageElement.appendChild(document.createTextNode(message));
                element.appendChild(messageElement);
            }

            return element;
        }

        public static Data fromDOM(Element element) {

            Data data = new Data();

            fromDOM(element, data);

            NodeList codeList = element.getElementsByTagName("Code");
            if (codeList.getLength() > 0) {
                String value = codeList.item(0).getTextContent();
                data.code = Integer.parseInt(value);
            }

            NodeList messageList = element.getElementsByTagName("Message");
            if (messageList.getLength() > 0) {
                String value = messageList.item(0).getTextContent();
                data.message = value;
            }

            return data;
        }

        @Override
        public String toXML() throws Exception {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();

            Element element = toDOM(document);
            document.appendChild(element);

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

            DOMSource domSource = new DOMSource(document);
            StringWriter sw = new StringWriter();
            StreamResult streamResult = new StreamResult(sw);
            transformer.transform(domSource, streamResult);

            return sw.toString();
        }

        public static Data fromXML(String xml) throws Exception {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xml)));

            Element element = document.getDocumentElement();
            return fromDOM(element);
        }
    }

}
