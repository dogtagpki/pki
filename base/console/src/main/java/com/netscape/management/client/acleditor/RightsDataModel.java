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

import java.util.Enumeration;

import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;

import com.netscape.management.client.acl.AttributeList;
import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiCheckCellEditor;
import com.netscape.management.nmclf.SuiCheckCellRenderer;

/**
 * The RightsDataModel defines the set of rights that
 * can be modified for a particular ACL rule, and
 * defines the appearance of the Table in which Rights
 * are edited.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/12/97
 */
public class RightsDataModel extends DataModelAdapter {
    protected static final String NoRightsSelectedError = "NoneSelected";

    protected static final int checkBoxWidth = 20;
    protected static final int numColumns = 2;

    protected AttributeList datacopy;
    protected Rule rule;
    protected String[] rights;

    /**
     * The default set of Rights for an Ldap ACL Rule.
     */
    protected static String[] defaultRights = { "read", "write", "add",
    "delete", "search", "compare", "selfwrite" };

    /**
     * The single Right value which corresponds to all Rights selected.
     */
    protected String allString() {
        return "all";
    }

    public RightsDataModel(ResourceSet rs, String _name, Rule _rule) {
        this(rs, _name, _rule, defaultRights);
    }

    public RightsDataModel(ResourceSet rs, String _name, Rule _rule,
            String[] rightsSet) {
        super(rs, _name);

        setHeaderVisible(false);

        rule = _rule;
        rights = rightsSet;

        datacopy = new AttributeList(rule.getRightsList());

        if (datacopy.containsAttribute(allString())) {
            datacopy.removeAttribute(allString());
            setAllSelected(true);
        }
    }

    public TableCellRenderer getColumnCellRenderer(int col) {
        switch (col) {
        case 0:
            SuiCheckCellRenderer renderer=new SuiCheckCellRenderer();
            renderer.getCheckBox().setToolTipText(getColumnToolTip(col));
            return renderer;

        default:
            return super.getColumnCellRenderer(col);
        }
    }

    public TableCellEditor getColumnCellEditor(int col) {
        switch (col) {
        case 0:
            SuiCheckCellEditor editor = new SuiCheckCellEditor();
            editor.getCheckBox().setToolTipText(getColumnToolTip(col));
            return editor;

        default:
            return null;
        }
    }

    public int getColumnWidth(int col) {
        switch (col) {
        case 0:
            return checkBoxWidth;

        default:
            return -1;
        }
    }

    public int getRowCount() {
        return rights.length;
    }
    public int getColumnCount() {
        return numColumns;
    }

    public Object getValueAt(int rowIndex, int columnIdentifier) {
        int col = columnIdentifier;

        switch (col) {
        case 0:
            return Boolean.valueOf(
                    datacopy.containsAttribute(rights[rowIndex]));

        case 1:
            return resources.getString(name, rights[rowIndex] + "Right");

        default:
            System.out.println("RightsDataModel:getValueAt():invalid column");
            return null;
        }
    }

    public void setValueAt(Object value, int rowIndex,
            int columnIdentifier) {
        int col = columnIdentifier;

        switch (col) {
        case 0:
            Boolean val = (Boolean) value;
            if (val.booleanValue())
                datacopy.setAttribute(rights[rowIndex]);
            else
                datacopy.removeAttribute(rights[rowIndex]);
            return;

        case 1:
            return;

        default:
            System.out.println("RightsDataModel:getValueAt():invalid column");
            return;
        }
    }

    protected void addRow(int selection) { }
    protected void deleteRow(int selection) { }
    protected void moveRow(int selection, boolean up) { }

    protected String complete() {
        int size = datacopy.size();

        if (size == 0)
            return NoRightsSelectedError;

        if (size == rights.length) {
            datacopy.removeAll();
            datacopy.setAttribute(allString());
        }

        AttributeList olddata = rule.getRightsList();

        Enumeration e = olddata.keys();

        while (e.hasMoreElements())
            rule.unSetRight((String)(e.nextElement()));

        e = datacopy.keys();

        while (e.hasMoreElements())
            rule.setRight((String)(e.nextElement()));

        return null;
    }

    protected void toggleSelectAll() {
        setAllSelected(!getAllSelectedValue());
    }

    protected void setAllSelected(boolean selected) {
        if (!selected) {
            datacopy.removeAll();
            return;
        }

        for (int i = 0 ; i < rights.length ; i++)
            datacopy.setAttribute(rights[i]);
    }

    protected boolean getAllSelectedValue() {
        return (datacopy.size() == rights.length);
    }
}
