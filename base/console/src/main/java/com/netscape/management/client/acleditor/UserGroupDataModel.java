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
package com.netscape.management.client.acleditor;

import javax.swing.Icon;
import javax.swing.JTextField;
import javax.swing.DefaultCellEditor;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableCellEditor;

import com.netscape.management.client.acl.LdapACL;
import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.acl.AttributeList;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;

/**
 * Data model for the user and group list component.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 9/1/97
 */

public class UserGroupDataModel extends DataModelAdapter {
    protected static final int iconWidth = 16;

    protected int dataColumn = 1;
    protected int numColumns = 2;

    protected static String[] attributeNames = { "userdn", "groupdn"};

    protected static final String UserDnAttr = "userdnattr";
    protected static final String AuthMethod = "authmethod";

    protected static final String ldapPrefix = "ldap:///";
    protected static final String ldapAnyone = "ldap:///anyone";

    protected Rule rule;
    protected AttributeList userdnattr;
    protected AttributeList authmethod;
    protected AttributeList[] attributeLists =
            new AttributeList[getTypeCount()];
    protected RemoteImage[] icons = new RemoteImage[getTypeCount()];

    public UserGroupDataModel(ResourceSet rs, String name, Rule _rule) {
        super(rs, name);
        setHeaderVisible(false);

        rule = _rule;

        userdnattr = new AttributeList(rule.getAttributeList(UserDnAttr));
        authmethod = new AttributeList(rule.getAttributeList(AuthMethod));

        for (int i = 0 ; i < getTypeCount(); i++) {
            attributeLists[i] = new AttributeList(
                    rule.getAttributeList(getTypeName(i)));
            icons[i] = new RemoteImage(resources.getString(name, "iconType"+i));
        }
    }

    public TableCellRenderer getColumnCellRenderer(int col) {
        switch (col) {
        case 0:
            DefaultTableCellRenderer dtcr = new DefaultTableCellRenderer() {
                        protected void setValue(Object value) {
                            setIcon((Icon) value);
                        }
                    };
            dtcr.setToolTipText(getColumnToolTip(col));
            return dtcr;

        default:
            return null;
        }
    }

    public TableCellEditor getColumnCellEditor(int col) {
        switch (col) {
        case 0:
            return null;

        default:
            JTextField renderer = new JTextField("");
            renderer.setToolTipText(getColumnToolTip(col));
            return new DefaultCellEditor(renderer);
        }
    }

    public int getColumnWidth(int col) {
        switch (col) {
        case 0:
            return iconWidth;

        default:
            return -1;
        }
    }

    public int getRowCount() {
        int cnt = 0;

        for (int i = 0 ; i < getTypeCount(); i++)
            cnt += attributeLists[i].size();

        return cnt;
    }

    public int getColumnCount() {
        return numColumns;
    }

    public int getTypeCount() {
        return attributeNames.length;
    }
    public String getTypeName(int i) {
        return attributeNames[i];
    }

    protected int getAttributeIndex(int index) {
        int cnt = 0;

        for (int i = 0 ; i < getTypeCount(); i++) {
            if (index - cnt < attributeLists[i].size())
                return i;
            cnt += attributeLists[i].size();
        }

        System.err.println("UserGroupDataModel:getAttributeIndex:invalid index");
        return -1;
    }

    protected int getAttributeOffset(int index) {
        int cnt = 0;

        for (int i = 0 ; i < getTypeCount(); i++) {
            if (index - cnt < attributeLists[i].size())
                return index - cnt;
            cnt += attributeLists[i].size();
        }

        System.err.println("UserGroupDataModel:getAttributeOffset:invalid index");
        return -1;
    }

    /**
      * Perform any necessary postprocessing of field String values here.
      */
    protected Object processOutputValue(Object val) {
        if (!(val instanceof String))
            return val;

        if (((String) val).startsWith(ldapPrefix))
            return ((String) val).substring(ldapPrefix.length());

        return val;
    }

    /**
      * Perform any necessary postprocessing of field String values here.
      */
    protected Object processInputValue(Object val) {
        if (!(val instanceof String))
            return val;

        if (!((String) val).startsWith(ldapPrefix))
            return ldapPrefix + (String) val;

        return val;
    }

    public Object getValueAt(int rowIndex, int columnIdentifier) {
        if (columnIdentifier == dataColumn)
            return processOutputValue(
                    attributeLists[getAttributeIndex(rowIndex)]
                    .getElementAt(getAttributeOffset(rowIndex)));

        return icons[getAttributeIndex(rowIndex)];
    }

    public String getUserDnAttrValue() {
        return userdnattr.generateList(",");
    }

    public String getAuthMethodValue() {
        return authmethod.generateList(",");
    }

    public void setUserDnAttrValue(String val) {
        userdnattr.removeAll();

        if (!val.equals(""))
            userdnattr.setAttribute(val);
    }

    public void setAuthMethodValue(String val) {
        authmethod.removeAll();

        if (!val.equals(""))
            authmethod.setAttribute(val);
    }

    public void setValueAt(Object value, int rowIndex,
            int columnIdentifier) {
        if (columnIdentifier != dataColumn)
            return;

        updateValue(attributeLists[getAttributeIndex(rowIndex)],
                getAttributeOffset(rowIndex), value);
    }

    protected void updateValue(AttributeList list, int index,
            Object value) {
        String val = (String)(list.getElementAt(index));

        if (val == null) {
            System.err.println("UserGroupDataModel:setValueAt():Unable to find value, no change.");
            return;
        }

        list.removeAttribute(val);
        list.setAttribute(processInputValue(value));
        validate();
    }

    protected void addRow(int selection) {}

    protected void addAttribute(String val, int type) {
        if (type >= getTypeCount()) {
            System.err.println("UserGroupDataModel:addAttribute():invalid type");
            return;
        }

        attributeLists[type].setAttribute(processInputValue(val));

        validate();
    }

    protected void validate() {
        int cnt = getRowCount();

        if (cnt == 1)
            return;

        if (cnt == 0) {
            attributeLists[0].setAttribute(ldapAnyone);
            return;
        }

        boolean contains = false;

        for (int i = 0 ; i < getTypeCount(); i++) {
            if (attributeLists[i].containsAttribute(ldapAnyone)) {
                contains = true;
                attributeLists[i].removeAttribute(ldapAnyone);
            }
        }

        if (!contains || (getRowCount() != 0))
            return;

        attributeLists[0].setAttribute(ldapAnyone);
    }

    protected void setAttributeEquality(boolean equals) {
        for (int i = 0 ; i < getTypeCount(); i++)
            attributeLists[i].setOperatorAll(!equals ? "!=" : "=");
    }

    protected boolean getAttributeEquality() {
        boolean eq = true;

        for (int i = 0 ; i < getTypeCount(); i++)
            if (attributeLists[i].getOperator().equals("!="))
                eq = false;

        return eq;
    }

    protected void deleteRow(int selection) {
        deleteValue(attributeLists[getAttributeIndex(selection)],
                getAttributeOffset(selection));
    }

    protected void deleteValue(AttributeList list, int selection) {
        String key = (String)(list.getElementAt(selection));

        if (key != null)
            list.removeAttribute(key);

        validate();
    }

    protected void moveRow(int selection, boolean up) {}

    protected void complete() {
        rule.updateAttributeList(UserDnAttr, userdnattr);
        rule.updateAttributeList(AuthMethod, authmethod);

        for (int i = 0 ; i < getTypeCount(); i++)
            rule.updateAttributeList(getTypeName(i), attributeLists[i]);
    }

    protected String[] getAuthMethods() {
        LdapACL acl = (LdapACL) getCallerData();

        if (acl == null)
            return null;

        return acl.getAuthMethodsSASL();
    }
}
