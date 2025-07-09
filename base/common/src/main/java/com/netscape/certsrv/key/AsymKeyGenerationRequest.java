//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.key;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedMap;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.RESTMessage;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class AsymKeyGenerationRequest extends KeyGenerationRequest  {

    // Asymmetric Key Usages
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final String SIGN = "sign";
    public static final String SIGN_RECOVER = "sign_recover";
    public static final String VERIFY = "verify";
    public static final String VERIFY_RECOVER = "verify_recover";
    public static final String WRAP = "wrap";
    public static final String UNWRAP = "unwrap";
    public static final String DERIVE = "derive";

    public AsymKeyGenerationRequest() {
        setClassName(getClass().getName());
    }

    public AsymKeyGenerationRequest(MultivaluedMap<String, String> form) {
        attributes.put(CLIENT_KEY_ID, form.getFirst(CLIENT_KEY_ID));
        attributes.put(KEY_SIZE, form.getFirst(KEY_SIZE));
        attributes.put(KEY_ALGORITHM, form.getFirst(KEY_ALGORITHM));
        attributes.put(KEY_USAGE, form.getFirst(KEY_USAGE));
        attributes.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        attributes.put(REALM,  form.getFirst(REALM));

        String usageString = attributes.get(KEY_USAGE);
        if (!StringUtils.isBlank(usageString)) {
            setUsages(new ArrayList<>(Arrays.asList(usageString.split(","))));
        }
        setClassName(getClass().getName());
    }

    public AsymKeyGenerationRequest(RESTMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    @Override
    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static List<String> getValidUsagesList() {
        List<String> list = new ArrayList<>();
        list.add(DERIVE);
        list.add(SIGN);
        list.add(DECRYPT);
        list.add(ENCRYPT);
        list.add(WRAP);
        list.add(UNWRAP);
        list.add(SIGN_RECOVER);
        list.add(VERIFY);
        list.add(VERIFY_RECOVER);

        return list;
    }

    @Override
    public Element toDOM(Document document) {
        Element element = document.createElement("AsymKeyGenerationRequest");
        toDOM(document, element);
        return element;
    }

    public static AsymKeyGenerationRequest fromDOM(Element element) {
        AsymKeyGenerationRequest request = new AsymKeyGenerationRequest();
        fromDOM(element, request);
        return request;
    }

    public static AsymKeyGenerationRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
