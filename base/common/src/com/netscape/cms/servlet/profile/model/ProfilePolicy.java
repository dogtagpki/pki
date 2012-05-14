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
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.profile.model;

import java.io.ByteArrayOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfilePolicy {
    @XmlAttribute
    private String id = null;

    @XmlElement
    private PolicyDefault def = null;

    @XmlElement
    private PolicyConstraint constraint = null;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public PolicyDefault getDef() {
        return def;
    }

    public void setDef(PolicyDefault def) {
        this.def = def;
    }

    public PolicyConstraint getConstraint() {
        return constraint;
    }

    public void setConstraint(PolicyConstraint constraint) {
        this.constraint = constraint;
    }

    public String toString() {
        try {
            JAXBContext context = JAXBContext.newInstance(ProfilePolicy.class);
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

}
