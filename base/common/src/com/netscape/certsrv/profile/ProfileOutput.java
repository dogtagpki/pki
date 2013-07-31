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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.property.Descriptor;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileOutput {

    @XmlAttribute
    private String  id;

    @XmlElement
    private String name;

    @XmlElement
    private String text;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @XmlElement
    private String classId;

    @XmlElement(name = "attributes")
    private List<ProfileAttribute> attrs = new ArrayList<ProfileAttribute>();


    public ProfileOutput() {
        // required for jaxb
    }

    public ProfileOutput(IProfileOutput output, String id, String classId, Locale locale) {
        this.name = output.getName(locale);
        this.id = id;
        this.classId = classId;
        Enumeration<String> names = output.getValueNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            addAttribute(new ProfileAttribute(name, null,
                    (Descriptor) output.getValueDescriptor(locale, name)));
        }
    }

    public String getClassId() {
        return classId;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    public List<ProfileAttribute> getAttrs() {
        return attrs;
    }

    public void setAttrs(List<ProfileAttribute> attrs) {
        this.attrs = attrs;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
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

}
