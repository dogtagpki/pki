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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 * @author ftweedal
 */
package com.netscape.certsrv.authority;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import org.jboss.resteasy.plugins.providers.atom.Link;

@XmlRootElement(name = "authority")
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthorityData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(AuthorityData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(AuthorityData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @XmlAttribute
    protected Boolean isHostAuthority;

    public Boolean getIsHostAuthority() {
        return isHostAuthority;
    }


    @XmlAttribute
    protected String id;

    public String getID() {
        return id;
    }


    @XmlAttribute
    protected String parentID;

    public String getParentID() {
        return parentID;
    }


    @XmlAttribute
    protected String dn;

    public String getDN() {
        return dn;
    }


    @XmlAttribute
    protected Boolean enabled;

    public Boolean getEnabled() {
        return enabled;
    }


    @XmlAttribute
    protected String description;

    public String getDescription() {
        return description;
    }


    protected Link link;

    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    protected AuthorityData() {
    }

    public AuthorityData(
            Boolean isHostAuthority,
            String dn, String id, String parentID,
            Boolean enabled, String description) {
        this.isHostAuthority = isHostAuthority;
        this.dn = dn;
        this.id = id;
        this.parentID = parentID;
        this.enabled = enabled;
        this.description = description;
    }

}
