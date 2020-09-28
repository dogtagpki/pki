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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.selftests;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="SelfTest")
public class SelfTestData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(SelfTestData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(SelfTestData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String id;
    Boolean enabledAtStartup;
    Boolean criticalAtStartup;
    Boolean enabledOnDemand;
    Boolean criticalOnDemand;

    Link link;

    @XmlAttribute(name="id")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="EnabledAtStartup")
    public Boolean isEnabledAtStartup() {
        return enabledAtStartup;
    }

    public void setEnabledAtStartup(Boolean enabledAtStartup) {
        this.enabledAtStartup = enabledAtStartup;
    }

    @XmlElement(name="CriticalAtStartup")
    public Boolean isCriticalAtStartup() {
        return criticalAtStartup;
    }

    public void setCriticalAtStartup(Boolean criticalAtStartup) {
        this.criticalAtStartup = criticalAtStartup;
    }

    @XmlElement(name="EnabledOnDemand")
    public Boolean isEnabledOnDemand() {
        return enabledOnDemand;
    }

    public void setEnabledOnDemand(Boolean enabledOnDemand) {
        this.enabledOnDemand = enabledOnDemand;
    }

    @XmlElement(name="CriticalOnDemand")
    public Boolean isCriticalOnDemand() {
        return criticalOnDemand;
    }

    public void setCriticalOnDemand(Boolean criticalOnDemand) {
        this.criticalOnDemand = criticalOnDemand;
    }

    @XmlElement(name="Link")
    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((criticalOnDemand == null) ? 0 : criticalOnDemand.hashCode());
        result = prime * result + ((enabledOnDemand == null) ? 0 : enabledOnDemand.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
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
        SelfTestData other = (SelfTestData) obj;
        if (criticalOnDemand == null) {
            if (other.criticalOnDemand != null)
                return false;
        } else if (!criticalOnDemand.equals(other.criticalOnDemand))
            return false;
        if (enabledOnDemand == null) {
            if (other.enabledOnDemand != null)
                return false;
        } else if (!enabledOnDemand.equals(other.enabledOnDemand))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static SelfTestData valueOf(String string) throws Exception {
        try {
            return (SelfTestData)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        SelfTestData before = new SelfTestData();
        before.setID("selftest1");
        before.setEnabledOnDemand(true);
        before.setCriticalOnDemand(false);

        String string = before.toString();
        System.out.println(string);

        SelfTestData after = SelfTestData.valueOf(string);
        System.out.println(before.equals(after));
    }
}
