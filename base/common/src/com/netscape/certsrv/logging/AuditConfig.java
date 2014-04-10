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

package com.netscape.certsrv.logging;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Audit")
@XmlAccessorType(XmlAccessType.NONE)
public class AuditConfig {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(AuditConfig.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(AuditConfig.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String status;
    Boolean signed;
    Integer interval;
    Integer bufferSize;

    Map<String, String> eventConfigs;

    Link link;

    @XmlElement(name="Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlElement(name="Signed")
    public Boolean getSigned() {
        return signed;
    }

    public void setSigned(Boolean signed) {
        this.signed = signed;
    }

    @XmlElement(name="Interval")
    public Integer getInterval() {
        return interval;
    }

    public void setInterval(Integer interval) {
        this.interval = interval;
    }

    @XmlElement(name="BufferSize")
    public Integer getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(Integer bufferSize) {
        this.bufferSize = bufferSize;
    }

    @XmlElement(name="Events")
    @XmlJavaTypeAdapter(EventConfigsAdapter.class)
    public Map<String, String> getEventConfigs() {
        return eventConfigs;
    }

    public void setEventConfigs(Map<String, String> eventConfigs) {
        this.eventConfigs = eventConfigs;
    }

    public static class EventConfigsAdapter extends XmlAdapter<EventConfigList, Map<String, String>> {

        public EventConfigList marshal(Map<String, String> map) {
            EventConfigList list = new EventConfigList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                EventConfig eventConfig = new EventConfig();
                eventConfig.name = entry.getKey();
                eventConfig.value = entry.getValue();
                list.entries.add(eventConfig);
            }
            return list;
        }

        public Map<String, String> unmarshal(EventConfigList list) {
            Map<String, String> map = new TreeMap<String, String>();
            for (EventConfig eventConfig : list.entries) {
                map.put(eventConfig.name, eventConfig.value);
            }
            return map;
        }
    }

    public static class EventConfigList {
        @XmlElement(name="Event")
        public List<EventConfig> entries = new ArrayList<EventConfig>();
    }

    public static class EventConfig {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
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
        result = prime * result + ((bufferSize == null) ? 0 : bufferSize.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((eventConfigs == null) ? 0 : eventConfigs.hashCode());
        result = prime * result + ((interval == null) ? 0 : interval.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((signed == null) ? 0 : signed.hashCode());
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
        AuditConfig other = (AuditConfig) obj;
        if (bufferSize == null) {
            if (other.bufferSize != null)
                return false;
        } else if (!bufferSize.equals(other.bufferSize))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (eventConfigs == null) {
            if (other.eventConfigs != null)
                return false;
        } else if (!eventConfigs.equals(other.eventConfigs))
            return false;
        if (interval == null) {
            if (other.interval != null)
                return false;
        } else if (!interval.equals(other.interval))
            return false;
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        if (signed == null) {
            if (other.signed != null)
                return false;
        } else if (!signed.equals(other.signed))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return super.toString();
        }
    }

    public static AuditConfig valueOf(String string) throws Exception {
        try {
            return (AuditConfig)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        AuditConfig before = new AuditConfig();
        before.setStatus("Enabled");
        before.setSigned(false);
        before.setInterval(10);
        before.setBufferSize(512);

        Map<String, String> eventConfigs = new TreeMap<String, String>();
        eventConfigs.put("event1", "mandatory");
        eventConfigs.put("event2", "enabled");
        eventConfigs.put("event3", "disabled");
        before.setEventConfigs(eventConfigs);

        String string = before.toString();
        System.out.println(string);

        AuditConfig after = AuditConfig.valueOf(string);
        System.out.println(before.equals(after));
    }
}
