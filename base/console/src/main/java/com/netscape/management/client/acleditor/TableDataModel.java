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

import java.util.Hashtable;
import java.util.Enumeration;

import javax.swing.JComboBox;
import javax.swing.DefaultCellEditor;
import javax.swing.table.TableCellEditor;

import com.netscape.management.client.acl.ACL;
import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.acl.AttributeList;
import com.netscape.management.client.console.ConsoleInfo;

/**
 * Data model for the table component.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 8/28/97
 */

public class TableDataModel extends DataModelAdapter implements SelectionListener {
    protected static final String RULE = "Rule";
    protected static final String USERGROUPS = "UserGroups";
    protected static final String HOSTS = "Hosts";
    protected static final String TIME = "Time";
    protected static final String ALLOWDENY = "AllowDeny";
    protected static final String RIGHTS = "Rights";

    protected static final String itemSeparator = " || ";
    protected static final String ldapPrefix = "ldap:///";

    protected static String[] defaultHeaders = { RULE, ALLOWDENY,
    USERGROUPS, HOSTS, TIME, RIGHTS };

    protected ConsoleInfo info;
    protected DataModelFactory dataFactory;
    protected WindowFactory windowFactory;
    protected String allow;
    protected String deny;
    protected Hashtable windows;
    protected ACL acl;

    public TableDataModel(DataModelFactory dmf, WindowFactory wf,
            ConsoleInfo ci) {
        this(dmf, wf, ci, defaultHeaders);
    }

    public TableDataModel(DataModelFactory dmf, WindowFactory wf,
            ConsoleInfo ci, String[] headers) {
        super(dmf.getResourceSet(), TableName, headers);

        info = ci;
        dataFactory = dmf;
        windowFactory = wf;
        allow = resources.getString(ACLName, "allow");
        deny = resources.getString(ACLName, "deny");
        windows = new Hashtable();

        acl = dataFactory.getACL(info, windowFactory);
        /*acl.retrieveACL(dataFactory.getACLRef(info));*/
    }

    public TableCellEditor getColumnCellEditor(int col) {
        String cid = (String) getColumnIdentifier(col);

        if (!cid.equals(ALLOWDENY)) {
            // DT 7/15/98
            //
            // Only on HPUX, the following call occasionally throws
            // a NullPointerException. However, this does not
            // appear to affect the ACL Editor in any way,
            // and it operates correctly after the printed
            // exception message. I can not explain the
            // exception, because it can only come from super
            // having a null value; and this should never occur
            // in a correct VM implementation...
            //
            // In any event, the only problem here appears to
            // be the printed exception message -- so we
            // catch the exception, and party on.
            //
            // Yet another wacko HP VM bug...
            //
            try {
                return super.getColumnCellEditor(col);
            } catch (NullPointerException npe) {

            }
        }

        JComboBox box = new JComboBox();
        box.addItem(allow);
        box.addItem(deny);
        box.setToolTipText(getColumnToolTip(col));
        return new DefaultCellEditor(box);
    }

    public boolean isCellEditable(int rowIndex, int columnIdentifier) {
        String cid = (String) getColumnIdentifier(columnIdentifier);
        return (cid.equals(ALLOWDENY));
    }

    public int getRowCount() {
        return acl.getRuleCount();
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        if (acl.syntaxOverrideSet())
            return checkValue("--");

        Rule r = acl.getRule(rowIndex);
        String cid = (String) getColumnIdentifier(columnIndex);

        if (cid.equals(RULE))
            return ((rowIndex + 1) + "");

        if (cid.equals(RIGHTS))
            return checkValue(generateAttributeList(r.getRightsList()));

        if (cid.equals(USERGROUPS))
            return checkValue(
                    generateAttributeList(r.getAttributeList("userdn"),
                    r.getAttributeList("groupdn"), ldapPrefix));

        if (cid.equals(HOSTS))
            return checkValue(
                    generateAttributeList(r.getAttributeList("dns"),
                    r.getAttributeList("ip")));

        if (cid.equals(TIME))
            return checkValue( generateAttributeList(
                    r.getAttributeList("timeofday"),
                    r.getAttributeList("dayofweek")));

        if (cid.equals(ALLOWDENY))
            return checkValue(r.getAllow() ? allow : deny);

        return checkValue("");
    }

    protected String checkValue(String s) {
        if (!s.equals(""))
            return s;

        return resources.getString(TableName, "emptyCellValue");
    }

    protected String generateAttributeList(AttributeList al) {
        if (al != null)
            return al.generateList(",");

        return "";
    }

    protected String generateAttributeList(AttributeList al1,
            AttributeList al2) {
        return generateAttributeList(al1, al2, null);
    }

    protected String generateAttributeList(AttributeList al1,
            AttributeList al2, String stripPrefix) {
        if (al1 == null) {
            if (al2 == null)
                return "";

            return al2.generateList(itemSeparator, stripPrefix, null);
        }

        if (al2 == null)
            return al1.generateList(itemSeparator, stripPrefix, null);

        return al1.generateList(itemSeparator, stripPrefix, null) +
                "," + al2.generateList(itemSeparator, stripPrefix, null);
    }

    protected void saveData() throws Exception {
        acl.updateACL(dataFactory.getACLRef(info));
    }

    protected void addRow(int selection) {
        if (selection == -1)
            acl.appendRule();
        else
            acl.insertRule(selection);
    }

    protected void deleteRow(int selection) {
        if (selection == -1)
            return;

        acl.deleteRule(selection);
    }

    protected void moveRow(int selection, boolean up) {
        if (selection == -1)
            return;

        if (up) {
            if (selection != 0) {
                acl.swapRules(selection, selection - 1);
                return;
            }
        } else {
            if (selection != getRowCount() - 1) {
                acl.swapRules(selection, selection + 1);
                return;
            }
        }

        System.err.println(
                "TableDataModel:moveRow():invalid parameters:selection=" +
                selection + ", up=" + up);
    }

    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        String cid = (String) getColumnIdentifier(columnIndex);

        if (!cid.equals(ALLOWDENY))
            return;

        acl.getRule(rowIndex).setAllow(((String) value).equals(allow));
    }

    public void show(ACLEditorWindow window, CallbackAction cb) {
        windows.put(window.getWindowName(), window);
        window.setCompletionCallback(new CallbackAction(cb) {
                    public void callback(Object arg) {
                        removeWindow((String) arg);
                    }
                }
                );
        window.show();
    }

    public void removeWindow(String windowName) {
        windows.remove(windowName);
    }

    public void dispose() {
        Enumeration e = windows.elements();

        while (e.hasMoreElements()) {
            ACLEditorWindow window = (ACLEditorWindow)(e.nextElement());
            window.dispose();
        }

        windows.clear();
    }

    protected boolean isFocusEnabled() {
        return !acl.syntaxOverrideSet();
    }

    public void showSyntaxWindow(CallbackAction cb) {
        ACLEditorWindow window = (ACLEditorWindow)(windows.get(SyntaxName));
        if (window == null)
            show(windowFactory.createSyntaxWindow(acl), cb);
        else
            window.toFront();
    }

    public void showAttributesWindow(CallbackAction cb) {
        ACLEditorWindow window =
                (ACLEditorWindow)(windows.get(AttributesName));
        if (window == null)
            show(windowFactory.createAttributesWindow(acl), cb);
        else
            window.toFront();
    }

    public void showTestACLWindow(CallbackAction cb) {
        show(windowFactory.createTestACLWindow(info,
                dataFactory.getACLRef(info)), cb);
    }

    public boolean isTestACLAvailable() {
        return false;
    }

    public void selectionNotify(int row, int col, int clickCount,
            CallbackAction cb) {
        if (row == -1)
            return;

        if (acl.syntaxOverrideSet())
            return;

        if (clickCount != 2)
            return; // must double-click to spawn a sub-window.

        Rule rule = acl.getRule(row);
        String cid = (String) getColumnIdentifier(col);

        if (cid.equals(USERGROUPS)) {
            ACLEditorWindow window =
                    (ACLEditorWindow)(windows.get(UserGroupName));
            if (window == null) {
                DataModelAdapter dma =
                        dataFactory.getUserGroupDataModel(rule);
                dma.setCallerData(acl); // DT 8/18/98 Hack to pass acl object
                show(windowFactory.createUserGroupWindow(dma, info), cb);
            } else
                window.toFront();
            return;
        }

        if (cid.equals(HOSTS)) {
            ACLEditorWindow window =
                    (ACLEditorWindow)(windows.get(HostsName));
            if (window == null)
                show(windowFactory.createHostsWindow(
                        dataFactory.getHostsDataModel(rule), info), cb);
            else
                window.toFront();
            return;
        }

        if (cid.equals(RIGHTS)) {
            ACLEditorWindow window =
                    (ACLEditorWindow)(windows.get(RightsName));
            if (window == null)
                show(windowFactory.createRightsWindow(
                        dataFactory.getRightsDataModel(rule)), cb);
            else
                window.toFront();
            return;
        }

        if (cid.equals(TIME)) {
            ACLEditorWindow window =
                    (ACLEditorWindow)(windows.get(TimeName));
            if (window == null)
                show(windowFactory.createTimeWindow(rule), cb);
            else
                window.toFront();
            return;
        }
    }
}
