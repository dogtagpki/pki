/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.acl;

import java.util.Vector;
import java.util.Hashtable;
import java.util.Enumeration;

public class AttributeList extends Hashtable {
    protected String conjunction = "and";

    public AttributeList() {
        super();
    }

    public AttributeList(Hashtable src) {
        super();

        if (src == null)
            return;

        Enumeration e = src.keys();

        while (e.hasMoreElements()) {
            Object key = e.nextElement();
            this.put(key, src.get(key));
        }
    }

    public void setConjunction(String _conjunction) {
        conjunction = _conjunction;
    }
    public void setAttribute(Object attr) {
        put(attr, "=");
    }
    public void setAttribute(Object attr, Object op) {
        put(attr, op);
    }
    public void removeAttribute(Object attr) {
        remove(attr);
    }
    public boolean containsAttribute(Object attr) {
        return containsKey(attr);
    }

    public void setOperatorAll(Object op) {
        Enumeration e = this.keys();

        while (e.hasMoreElements()) {
            Object key = e.nextElement();
            this.put(key, op);
        }
    }

    public String getOperator() {
        // hack.
        Enumeration e = this.keys();

        if (!e.hasMoreElements())
            return "";

        return (String)(this.get(e.nextElement()));
    }

    public void removeAll() {
        Enumeration e = this.keys();

        while (e.hasMoreElements()) {
            Object key = e.nextElement();
            this.remove(key);
        }
    }

    public Object getElementAt(int i) {
        int cnt = 0;
        Enumeration e = this.keys();

        while (e.hasMoreElements()) {
            Object val = e.nextElement();

            if (cnt++ == i)
                return val;
        }

        return null;
    }

    protected String generateExpression(String name) {
        return generateExpression(name, conjunction);
    }

    protected String generateExpression(String name, String _conjunction) {
        StringBuffer expr = new StringBuffer();

        if (size() == 0)
            return expr.toString();

        // DT 4/20/98
        //
        // Since we now support multiple comparators in the attribute list, we have
        // to sort them out before we can generate the list.

        Hashtable comparators = new Hashtable();

        Enumeration e = this.keys();
        while (e.hasMoreElements()) {
            String value = (String)(e.nextElement());
            String op = (String)(this.get(value));

            if (!comparators.containsKey(op))
                comparators.put(op, new Vector());

            ((Vector)(comparators.get(op))).addElement(value);
        }

        if (comparators.size() > 1)
            expr.append("(");

        e = comparators.keys();
        while (true) {
            String op = (String)(e.nextElement());
            Vector v = (Vector)(comparators.get(op));

            expr.append(name);
            expr.append(" ");
            expr.append(op);
            expr.append(" \"");
            expr.append(generateList(v.elements()));
            expr.append("\"");

            if (!e.hasMoreElements())
                break;

            expr.append(" ");
            expr.append(_conjunction);
            expr.append(" ");
        }

        if (comparators.size() > 1)
            expr.append(")");

        return expr.toString();
    }

    public String generateList(Enumeration e, String sep,
            String stripPrefix, String stripSuffix) {
        StringBuffer s = new StringBuffer();

        if (!e.hasMoreElements())
            return s.toString();

        while (true) {
            String next = (String)(e.nextElement());

            if ((stripPrefix != null) && next.startsWith(stripPrefix))
                next = next.substring(stripPrefix.length());

            if ((stripSuffix != null) && next.endsWith(stripSuffix))
                next = next.substring(0,
                        next.length() - stripSuffix.length());

            s.append(next);

            if (!e.hasMoreElements())
                break;

            s.append(sep);
        }

        return s.toString();

    }

    public String generateList(String sep, String stripPrefix,
            String stripSuffix) {
        return generateList(this.keys(), sep, stripPrefix, stripSuffix);
    }

    public String generateList(Enumeration e) {
        return generateList(e, "||", null, null);
    }
    public String generateList(String sep) {
        return generateList(this.keys(), sep, null, null);
    }
    public String generateList() {
        return generateList(this.keys(), "||",null, null);
    }
}
