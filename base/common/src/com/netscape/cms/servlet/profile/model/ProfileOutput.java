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
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileOutput {

    public ProfileOutput() {
        // required for jaxb
    }

    @XmlElement
    private String outputId;

    @XmlElement(name = "attributes")
    private List<ProfileAttribute> attrs = new ArrayList<ProfileAttribute>();

    @XmlElement
    private String name;

    @XmlElement
    private String text;

    public String getOutputId() {
        return outputId;
    }

    public void setOutputId(String OutputId) {
        this.outputId = OutputId;
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

}
