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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.property.Descriptor;

@XmlRootElement(name="Input")
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileInput {

    @XmlAttribute(name="id")
    private String id;

    @XmlElement(name="ClassID")
    private String classId;

    @XmlElement(name="Name")
    private String name;

    @XmlElement(name="Text")
    private String text;

    @XmlElement(name = "Attribute")
    private List<ProfileAttribute> attrs = new ArrayList<ProfileAttribute>();

    @XmlElement(name = "ConfigAttribute")
    private List<ProfileAttribute> configAttrs = new ArrayList<ProfileAttribute>();

    public ProfileInput() {
        // required for jaxb
    }

    public ProfileInput(String id, String name, String classId) {
        this.id = id;
        this.name = name;
        this.classId = classId;
    }

    public ProfileInput(IProfileInput input, String id, String classId, Locale locale) {
        this(id, input.getName(locale), classId);
        Enumeration<String> names = input.getValueNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            addAttribute(new ProfileAttribute(name, null,
                    (Descriptor) input.getValueDescriptor(locale, name)));
        }
    }

    public String getClassId() {
        return classId;
    }

    public String getName() {
        return name;
    }

    public String getText() {
        return text;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

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

    public Collection<ProfileAttribute> getAttributes() {
        return attrs;
    }

    public void setAttributes(Collection<ProfileAttribute> attrs) {
        this.attrs.clear();
        this.attrs.addAll(attrs);
    }

    public ProfileAttribute getAttribute(String name) {
        for (ProfileAttribute attr : attrs) {
            if (attr.getName().equals(name)) return attr;
        }
        return null;
    }

    public void addAttribute(ProfileAttribute attr) {
        attrs.add(attr);
    }

    public void removeAttribute(String name) {
        attrs.remove(name);
    }

    public void clearAttributes() {
        attrs.clear();
    }

    public List<ProfileAttribute> getConfigAttrs() {
        return configAttrs;
    }

    public void setConfigAttrs(List<ProfileAttribute> configAttrs) {
        this.configAttrs = configAttrs;
    }

    public void addConfigAttribute(ProfileAttribute configAttr) {
        configAttrs.add(configAttr);
    }

    public void removeConfigAttribute(ProfileAttribute configAttr) {
        configAttrs.remove(configAttr);
    }

    public void clearConfigAttributes() {
        configAttrs.clear();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attrs == null) ? 0 : attrs.hashCode());
        result = prime * result + ((classId == null) ? 0 : classId.hashCode());
        result = prime * result + ((configAttrs == null) ? 0 : configAttrs.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((text == null) ? 0 : text.hashCode());
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
        ProfileInput other = (ProfileInput) obj;
        if (attrs == null) {
            if (other.attrs != null)
                return false;
        } else if (!attrs.equals(other.attrs))
            return false;
        if (classId == null) {
            if (other.classId != null)
                return false;
        } else if (!classId.equals(other.classId))
            return false;
        if (configAttrs == null) {
            if (other.configAttrs != null)
                return false;
        } else if (!configAttrs.equals(other.configAttrs))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (text == null) {
            if (other.text != null)
                return false;
        } else if (!text.equals(other.text))
            return false;
        return true;
    }

    public static ProfileInput fromXML(String string) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(ProfileInput.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (ProfileInput) unmarshaller.unmarshal(new StringReader(string));
    }

    public String toXML() throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(ProfileInput.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static void main(String args[]) throws Exception {

        ProfileInput before = new ProfileInput("i1", "SubjectNameInput", null);
        before.addAttribute(new ProfileAttribute("sn_uid", "jmagne", null));
        before.addAttribute(new ProfileAttribute("sn_e", "jmagne@redhat.com", null));
        before.addAttribute(new ProfileAttribute("sn_c", "US", null));
        before.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        before.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        before.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        before.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        before.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        before.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));

        String xml = before.toXML();
        System.out.println(xml);

        ProfileInput after = ProfileInput.fromXML(xml);
        System.out.println(after.toXML());

        System.out.println(before.equals(after));
    }
}
