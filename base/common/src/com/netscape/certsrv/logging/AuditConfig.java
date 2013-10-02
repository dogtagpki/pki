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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
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

    Boolean enabled;
    Boolean signed;
    Integer interval;
    Integer bufferSize;
    Collection<String> mandatoryEvents = new TreeSet<String>();
    Map<String, Boolean> optionalEvents = new TreeMap<String, Boolean>();

    Link link;

    @XmlElement(name="Enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
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

    @XmlElement(name="MandatoryEvents")
    @XmlJavaTypeAdapter(MandatoryEventsAdapter.class)
    public Collection<String> getMandatoryEvents() {
        return mandatoryEvents;
    }

    public void setMandatoryEvents(Collection<String> mandatoryEvents) {
        this.mandatoryEvents.clear();
        this.mandatoryEvents.addAll(mandatoryEvents);
    }

    public void addMandatoryEvent(String event) {
        mandatoryEvents.add(event);
    }

    public void removeMandatoryEvent(String event) {
        mandatoryEvents.remove(event);
    }

    @XmlElement(name="OptionalEvents")
    @XmlJavaTypeAdapter(OptionalEventsAdapter.class)
    public Map<String, Boolean> getOptionalEvents() {
        return optionalEvents;
    }

    public void setOptionalEvents(Map<String, Boolean> optionalEvents) {
        this.optionalEvents.clear();
        this.optionalEvents.putAll(optionalEvents);
    }

    public Collection<String> getOptionalEventNames() {
        return optionalEvents.keySet();
    }

    public Boolean getOptionalEvent(String name) {
        return optionalEvents.get(name);
    }

    public void setOptionalEvent(String name, Boolean value) {
        optionalEvents.put(name, value);
    }

    public Boolean removeOptionalEvent(String name) {
        return optionalEvents.remove(name);
    }

    public static class MandatoryEventsAdapter extends XmlAdapter<EventList, Collection<String>> {

        public EventList marshal(Collection<String> input) {
            EventList output = new EventList();
            for (String name : input) {
                Event event = new Event();
                event.name = name;
                output.entries.add(event);
            }
            return output;
        }

        public Collection<String> unmarshal(EventList input) {
            Collection<String> output = new TreeSet<String>();
            for (Event event : input.entries) {
                output.add(event.name);
            }
            return output;
        }
    }

    public static class OptionalEventsAdapter extends XmlAdapter<EventList, Map<String, Boolean>> {

        public EventList marshal(Map<String, Boolean> map) {
            EventList list = new EventList();
            for (Map.Entry<String, Boolean> entry : map.entrySet()) {
                Event event = new Event();
                event.name = entry.getKey();
                event.value = entry.getValue();
                list.entries.add(event);
            }
            return list;
        }

        public Map<String, Boolean> unmarshal(EventList list) {
            Map<String, Boolean> map = new LinkedHashMap<String, Boolean>();
            for (Event event : list.entries) {
                map.put(event.name, event.value);
            }
            return map;
        }
    }

    public static class EventList {
        @XmlElement(name="Event")
        public List<Event> entries = new ArrayList<Event>();
    }

    public static class Event {

        @XmlAttribute
        public String name;

        @XmlValue
        public Boolean value;
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
        result = prime * result + ((enabled == null) ? 0 : enabled.hashCode());
        result = prime * result + ((optionalEvents == null) ? 0 : optionalEvents.hashCode());
        result = prime * result + ((interval == null) ? 0 : interval.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((mandatoryEvents == null) ? 0 : mandatoryEvents.hashCode());
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
        if (enabled == null) {
            if (other.enabled != null)
                return false;
        } else if (!enabled.equals(other.enabled))
            return false;
        if (optionalEvents == null) {
            if (other.optionalEvents != null)
                return false;
        } else if (!optionalEvents.equals(other.optionalEvents))
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
        if (mandatoryEvents == null) {
            if (other.mandatoryEvents != null)
                return false;
        } else if (!mandatoryEvents.equals(other.mandatoryEvents))
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
        before.setEnabled(true);
        before.setSigned(false);
        before.setInterval(10);
        before.setBufferSize(512);
        before.addMandatoryEvent("event1");
        before.addMandatoryEvent("event2");
        before.setOptionalEvent("event3", true);
        before.setOptionalEvent("event4", false);

        String string = before.toString();
        System.out.println(string);

        AuditConfig after = AuditConfig.valueOf(string);
        System.out.println(before.equals(after));
    }
}
