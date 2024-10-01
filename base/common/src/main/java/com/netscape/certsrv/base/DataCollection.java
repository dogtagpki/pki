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
import java.util.Objects;

/**
 * @author Endi S. Dewata
 */
public class DataCollection<E> {

    protected Integer total;
    protected Collection<E> entries = new ArrayList<>();

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
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

    @Override
    public int hashCode() {
        return Objects.hash(entries, total);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DataCollection other = (DataCollection) obj;
        return Objects.equals(entries, other.entries) && Objects.equals(total, other.total);
    }
}
