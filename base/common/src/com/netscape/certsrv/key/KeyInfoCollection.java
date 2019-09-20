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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.key;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import com.netscape.certsrv.base.DataCollection;

@XmlRootElement(name = "KeyInfoCollection")
public class KeyInfoCollection extends DataCollection<KeyInfo> {

    @XmlElementRef
    public Collection<KeyInfo> getEntries() {
        return super.getEntries();
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.writeValueAsString(this);
    }

    public static KeyInfoCollection fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, KeyInfoCollection.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {

        KeyInfoCollection collection = new KeyInfoCollection();

        KeyInfo key1 = new KeyInfo();
        key1.setClientKeyID("key1");
        key1.setStatus("active");
        collection.addEntry(key1);

        KeyInfo key2 = new KeyInfo();
        key2.setClientKeyID("key2");
        key2.setStatus("active");
        collection.addEntry(key2);

        String json = collection.toJSON();
        System.out.println(json);
    }
}
