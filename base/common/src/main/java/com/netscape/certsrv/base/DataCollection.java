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

package com.netscape.certsrv.base;

import java.util.ArrayList;
import java.util.Collection;

import javax.xml.bind.annotation.XmlElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
public class DataCollection<E> {

    int total;
    Collection<E> entries = new ArrayList<E>();
    Collection<Link> links = new ArrayList<Link>();

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public Collection<E> getEntries() {
        return entries;
    }

    public void setEntries(Collection<E> entries) {
        this.entries.clear();
        if (entries == null) return;
        this.entries.addAll(entries);
    }

    public void addEntry(E entry) {
        entries.add(entry);
    }

    public void removeEntry(E entry) {
        entries.remove(entry);
    }

    @XmlElement(name="Link")
    public Collection<Link> getLinks() {
        return links;
    }

    public void setLinks(Collection<Link> links) {
        this.links.clear();
        if (links == null) return;
        this.links.addAll(links);
    }

    public void addLink(Link link) {
        links.add(link);
    }

    public void removeLink(Link link) {
        links.remove(link);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entries == null) ? 0 : entries.hashCode());
        result = prime * result + ((links == null) ? 0 : links.hashCode());
        result = prime * result + total;
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
        DataCollection<E> other = (DataCollection<E>) obj;
        if (entries == null) {
            if (other.entries != null)
                return false;
        } else if (!entries.equals(other.entries))
            return false;
        if (links == null) {
            if (other.links != null)
                return false;
        } else if (!links.equals(other.links))
            return false;
        if (total != other.total)
            return false;
        return true;
    }
}
