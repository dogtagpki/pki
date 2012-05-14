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
package com.netscape.cms.servlet.profile.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

public class ProfileInput {

    public ProfileInput() {
        // required for jaxb
    }

    @XmlElement
    public String getInputId() {
        return inputId;
    }

    private String inputId;

    @XmlJavaTypeAdapter(InputAttrsAdapter.class)
    public Map<String, String> InputAttrs = new LinkedHashMap<String, String>();

    public void setInputAttr(String name, String value) {
        InputAttrs.put(name, value);
    }

    public void setInputId(String inputId) {
        this.inputId = inputId;
    }

    public static class InputAttrsAdapter extends XmlAdapter<InputAttrList, Map<String, String>> {

        public InputAttrList marshal(Map<String, String> map) {
            InputAttrList list = new InputAttrList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                Attribute attribute = new Attribute();
                attribute.name = entry.getKey();
                attribute.value = entry.getValue();
                list.attributes.add(attribute);
            }
            return list;
        }

        public Map<String, String> unmarshal(InputAttrList list) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            for (Attribute attribute : list.attributes) {
                map.put(attribute.name, attribute.value);
            }
            return map;
        }
    }

    public static class InputAttrList {
        @XmlElement(name = "InputAttr")
        public List<Attribute> attributes = new ArrayList<Attribute>();
    }

    public static class Attribute {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
    }

    public Map<String, String> getAttributes() {
        return InputAttrs;
    }
}
