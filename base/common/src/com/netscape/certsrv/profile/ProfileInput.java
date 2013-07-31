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
package com.netscape.certsrv.profile;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

import com.netscape.certsrv.property.Descriptor;

public class ProfileInput {
    private String id;
    private String classId;
    private String name;
    private String text;
    private List<ProfileAttribute> attrs = new ArrayList<ProfileAttribute>();
    private List<ProfileAttribute> configAttrs = new ArrayList<ProfileAttribute>();

    public ProfileInput() {
        // required for jaxb
    }

    public ProfileInput(IProfileInput input, String id, String classId, Locale locale) {
        this.name = input.getName(locale);
        this.id = id;
        this.classId = classId;
        Enumeration<String> names = input.getValueNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            addAttribute(new ProfileAttribute(name, null,
                    (Descriptor) input.getValueDescriptor(locale, name)));
        }
    }

    @XmlElement
    public String getClassId() {
        return classId;
    }

    @XmlElement
    public String getName() {
        return name;
    }

    @XmlElement
    public String getText() {
        return text;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    @XmlAttribute
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setText(String text) {
        this.text = text;
    }

    @XmlElement(name = "attribute")
    public List<ProfileAttribute> getAttrs() {
        return attrs;
    }

    public void setAttrs(List<ProfileAttribute> attrs) {
        this.attrs = attrs;
    }

    public void addAttribute(ProfileAttribute attr) {
        attrs.add(attr);
    }

    public void removeAttribute(ProfileAttribute attr) {
        attrs.remove(attr);
    }

    public void clearAttributes() {
        attrs.clear();
    }

    @XmlElement(name = "config_attribute")
    public List<ProfileAttribute> getConfigAttrs() {
        return configAttrs;
    }

    public void setConfigAttrs(List<ProfileAttribute> configAttrs) {
        this.configAttrs = configAttrs;
    }

    public void addConfigAttribute(ProfileAttribute configAttr) {
        attrs.add(configAttr);
    }

    public void removeConfigAttribute(ProfileAttribute configAttr) {
        attrs.remove(configAttr);
    }

    public void clearConfigAttributes() {
        configAttrs.clear();
    }

}
