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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.netscape.certsrv.base.Link;

@XmlRootElement(name = "KeyDataInfos")
public class KeyDataInfos {

    protected Collection<KeyDataInfo> keyInfos = new ArrayList<KeyDataInfo>();
    protected List<Link> links = new ArrayList<Link>();

    /**
     * @return the keyInfos
     */
    @XmlElementRef
    public Collection<KeyDataInfo> getKeyInfos() {
        return keyInfos;
    }

    /**
     * @param keyInfos the keyInfos to set
     */
    public void setKeyInfos(Collection<KeyDataInfo> keyInfos) {
        this.keyInfos = keyInfos;
    }

    /**
     * @param keyInfo the keyInfo to add
     */
    public void addKeyInfo(KeyDataInfo keyInfo) {
        keyInfos.add(keyInfo);
    }

    /**
     * @return the links
     */
    @XmlElementRef
    public List<Link> getLinks() {
        return links;
    }

    /**
     * @param links the links to set
     */
    public void setLinks(List<Link> links) {
        this.links = links;
    }

    @XmlTransient
    public String getNext() {
        if (links == null) {
            return null;
        }
        for (Link link : links) {
            if ("next".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }

    @XmlTransient
    public String getPrevious() {
        if (links == null) {
            return null;
        }
        for (Link link : links) {
            if ("previous".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }
}
