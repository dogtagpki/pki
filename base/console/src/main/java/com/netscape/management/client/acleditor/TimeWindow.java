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

import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import java.awt.event.ActionEvent;
import java.awt.Insets;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;

import java.util.Enumeration;

import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.acl.LdapRule;
import com.netscape.management.client.acl.AttributeList;

/**
 * Time Selection Window.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 9/4/97
 */

public class TimeWindow extends ACLEditorWindow {
    protected int textWidth = 10;

    Rule rule;
    AttributeList timecopy, daycopy;
    JTextField begMenu, endMenu;
    JComboBox dayMenu;
    String _sLocalizeDay[];
    static String _sEnglishDay[] = {"Sunday","Monday","Tuesday","Wednesday",
    "Thursday","Friday","Saturday"};

    public TimeWindow(String name, WindowFactory wf, Rule _rule) {
        super(wf, name, wf.getSessionIdentifier());

        rule = _rule;

        timecopy = new AttributeList(
                rule.getAttributeList(LdapRule.timeAttribute));
        daycopy = new AttributeList(
                rule.getAttributeList(LdapRule.dayAttribute));

        JPanel bp = createStandardLayout();

        GridBagLayout gbl = (GridBagLayout)(getContentPane().getLayout());
        GridBagConstraints gbc = gbl.getConstraints(getComponent("main"));
        gbc.insets = new Insets(PAD, PAD * 3 / 2, 0, PAD * 3 / 2);
        gbl.setConstraints(getComponent("main"), gbc);

        gbc = new GridBagConstraints();

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 2 * PAD, PAD);
        gbc.ipady = 0;
        bp.add(createInstruction("main2"), gbc);

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.ipady = PAD / 2;
        bp.add(createInstruction("beginning"), gbc);

        resetConstraints(gbc);
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        bp.add(begMenu = createTextField("beginningMenu", 4, null), gbc);

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.ipady = PAD / 2;
        bp.add(createInstruction("end"), gbc);

        resetConstraints(gbc);
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        bp.add(endMenu = createTextField("endMenu", 4, null), gbc);

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.ipady = PAD / 2;
        bp.add(createInstruction("day"), gbc);

        resetConstraints(gbc);
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        bp.add(dayMenu = createComboBox("dayMenu", null), gbc);

        setResizable(false);
        populateMenus();
        populateData();

        pack();
    }

    protected void populateMenus() {
        // populate time menus with houly entries

        for (int i = 0 ; i < 24 ; i++) {
            String time = resources.getString(TimeName, "hour" + i);

            if (time == null)
                time = getTime24ForHour(i);

            begMenu.setText(time);
            endMenu.setText(time);
        }

        // populate day menu
        _sLocalizeDay = new String[7];
        for (int i = 0 ; i < 7 ; i++) {
            String sDay = resources.getString(TimeName, "day" + i);
            dayMenu.addItem(sDay);
            _sLocalizeDay[i] = sDay;
        }
        dayMenu.addItem("");
    }

    protected String getTime24ForHour(int hour) {
        return new String(((hour < 10) ? "0" : "") + hour + "00");
    }

    protected void populateData() {
        int cnt = timecopy.size();

        if ((cnt == 1) || (cnt == 2)) {
            Enumeration e = timecopy.keys();

            while (e.hasMoreElements()) {
                String time = (String)(e.nextElement());
                String comp = (String)(timecopy.get(time));

                if (comp.charAt(0) == '>')
                    begMenu.setText(time);
                else if (comp.charAt(0) == '<')
                    endMenu.setText(time);
            }
        }

        if (daycopy.size() > 0) {
            Enumeration e1 = daycopy.keys();
            String sDay = (String)(e1.nextElement());
            int i;
            for (i = 0; i < 7; i++) {
                if (sDay.equalsIgnoreCase(_sEnglishDay[i])) {
                    break;
                }
            }
            dayMenu.setSelectedIndex(i);
        }
    }

    protected String packageTime(String t) {
        int length = t.length();
        for (int i = 0; i < 4 - length; i++) {
            t = "0"+t;
        }
        return t;
    }

    protected void save(ActionEvent e) {
        timecopy.removeAll();
        daycopy.removeAll();

        String t;

        if (!(t = (String)(begMenu.getText())).equals("")) {
            t = packageTime(t);
            timecopy.setAttribute(t, ">");
        }
        if (!(t = (String)(endMenu.getText())).equals("")) {
            t = packageTime(t);
            timecopy.setAttribute(t, "<");
        }

        rule.updateAttributeList(LdapRule.timeAttribute, timecopy);

        if (!(t = (String)(dayMenu.getSelectedItem())).equals("")) {
            for (int i = 0; i < 7; i++) {
                if (t.equalsIgnoreCase(_sLocalizeDay[i])) {
                    t = _sEnglishDay[i];
                    break;
                }
            }
            // if we don't find the string, use the original one
            daycopy.setAttribute(t);
        }

        rule.updateAttributeList(LdapRule.dayAttribute, daycopy);

        super.save(e);
    }
}
