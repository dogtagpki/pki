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
package com.netscape.cmsutil.radius;

import java.util.Enumeration;
import java.util.Vector;

public class AttributeSet {
    private Vector _attrs = new Vector();

    public AttributeSet() {
    }

    public void addAttribute(Attribute attr) {
        _attrs.addElement(attr);
    }

    public int size() {
        return _attrs.size();
    }

    public Enumeration getAttributes() {
        return _attrs.elements();
    }

    public Attribute getAttributeByType(int type) {
        int l = _attrs.size();

        for (int i = 0; i < l; i++) {
            Attribute attr = getAttributeAt(i);

            if (attr.getType() == type)
                return attr;
        }
        return null;
    }

    public Attribute getAttributeAt(int pos) {
        return (Attribute) _attrs.elementAt(pos);
    }
}
