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

import java.io.StreamTokenizer;
import java.io.Writer;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * The LdapRule overrides the Rule class to tweak the
 * ONE syntax for directory-resident ACLs.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/27/97
 * @see ACL
 */
public class LdapRule extends Rule {
    public static final String timeAttribute = "timeofday";
    public static final String dayAttribute = "dayofweek";
    public static final String userAttribute = "userdn";
    public static final String groupAttribute = "groupdn";
    public static final String hostAttribute = "dns";
    public static final String ipaddrAttribute = "ip";

    public LdapRule(StreamTokenizer st) throws IOException {
        super(st);
    }

    public LdapRule() {
        super();
    }

    protected void setDefaults() {
        setAllow(false); // DT 8/5/98 -- change default to deny
        setRight("all");
        setAttribute("userdn", "ldap:///anyone");
    }

    protected String newLine() {
        return " ";
    }
    protected String indent() {
        return "";
    }

    /**
      * Write the rule content to the destination ACL via the Writer.
      * This version contains special handling to deal with specific
      * logic of LDAP acls.
      *
      * @param w a valid open Writer.
      *
      */
    protected void writeContent(Writer w) throws IOException {
        if (syntaxOverrideSet()) {
            w.write(syntax + newLine());
            return;
        }

        if (attr.size() == 0)
            return;

        // Create LdapACL with the following logic:
        //
        // (time) and (day) and (user or group) and (host or ip) and (all other attributes)
        //

        Hashtable tempStorage = new Hashtable();

        String[] s1 = { timeAttribute, dayAttribute };

        for (int i = 0 ; i < s1.length ; i++) {
            if (processAttribute(s1[i], w, tempStorage))
                return;
        }

        String[] s2 = { userAttribute, groupAttribute };
        if (processAttributes(s2, w, tempStorage))
            return;

        String[] s3 = { hostAttribute, ipaddrAttribute };
        if (processAttributes(s3, w, tempStorage))
            return;

        w.write("(");

        Enumeration e = attr.keys();

        while (true) {
            String key = (String)(e.nextElement());

            w.write(indent() +
                    getAttributeList(key).generateExpression(key));

            if (!e.hasMoreElements()) {
                w.write(");" + newLine());
                restoreAttributeLists(tempStorage);
                return;
            }

            w.write(" or" + newLine());
        }
    }

    protected boolean processAttribute(String name, Writer w,
            Hashtable tempStorage) throws IOException {
        AttributeList al = getAttributeList(name);

        if (al == null)
            return false;

        w.write(indent() + al.generateExpression(name));

        tempStorage.put(name, al);
        removeAttributeList(name);

        if (attr.size() == 0) {
            w.write(";" + newLine());
            restoreAttributeLists(tempStorage);
            return true;
        }

        w.write(" and" + newLine());
        return false;
    }

    protected boolean processAttributes(String[] names, Writer w,
            Hashtable tempStorage) throws IOException {
        // count existing attributes in array

        int count = 0;

        for (int i = 0 ; i < names.length ; i++)
            if (attr.containsKey(names[i]))
                count++;

        if (count == 0)
            return false;

        boolean parens = (count > 1);

        if (parens)
            w.write("(");

        for (int i = 0 ; i < names.length ; i++) {
            AttributeList al = getAttributeList(names[i]);

            if (al == null)
                continue;

            w.write(indent() + al.generateExpression(names[i]));

            tempStorage.put(names[i], al);
            removeAttributeList(names[i]);

            if (--count == 0) {
                if (parens)
                    w.write(")");
            } else
                w.write(" or" + newLine());
        }

        if (attr.size() == 0) {
            w.write(";" + newLine());
            restoreAttributeLists(tempStorage);
            return true;
        }

        w.write(" and" + newLine());
        return false;
    }

    protected void restoreAttributeLists(Hashtable h) {
        Enumeration e = h.keys();

        while (e.hasMoreElements()) {
            String key = (String)(e.nextElement());
            setAttributeList(key, (AttributeList)(h.get(key)));
        }
    }
}
