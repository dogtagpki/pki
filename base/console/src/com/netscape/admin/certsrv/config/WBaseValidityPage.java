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
package com.netscape.admin.certsrv.config;

import java.awt.*;
import java.text.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * CA signing cert for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class WBaseValidityPage extends WizardBasePanel {
    protected String mPanelName = "";
    protected JTextField mBYear, mBMonth, mBDay, mBHour, mBMin, mBSec;
    protected JTextField mEYear, mEMonth, mEDay, mEHour, mEMin, mESec;
    protected final static String DATE_PATTERN = "dd/MM/yyyy:HH:mm:ss";
    protected Date mBeforeDate, mAfterDate;
    protected boolean mWarningDisplayed = false;

    public WBaseValidityPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
    }

    public boolean validatePanel() {
        String beginYear = mBYear.getText().trim();
        String afterYear = mEYear.getText().trim();
        String beginMonth = mBMonth.getText().trim();
        String afterMonth = mEMonth.getText().trim();
        String beginDay = mBDay.getText().trim();
        String afterDay = mEDay.getText().trim();
        String beginHour = mBHour.getText().trim();
        String afterHour = mEHour.getText().trim();
        String beginMin = mBMin.getText().trim();
        String afterMin = mEMin.getText().trim();
        String beginSec = mBSec.getText().trim();
        String afterSec = mESec.getText().trim();

        int bYear = Integer.parseInt(beginYear);
        int aYear = Integer.parseInt(afterYear);

/*
POSIX timestamps used in most UNIX systems are 32-bit signed integers,
which gives you 2^31 seconds or about 68 years of useful time.  The
epoch is 1970-01-01 00:00:00, so the counter will overflow sometime in
January 2038.
*/
 //       if (bYear > 2032 || aYear > 2032) {
        if (bYear > 2037 || aYear > 2037) {
            String errorMsg = mResource.getString(mPanelName+
              "_LABEL_MAXYEAR_LABEL");
            JOptionPane.showMessageDialog(mParent, errorMsg, "Warning",
              JOptionPane.WARNING_MESSAGE,
              CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON));
            return false;
        }

        String beginDateStr = beginDay+"/"+beginMonth+"/"+beginYear+":"
          +beginHour+":"+beginMin+":"+beginSec;
        String endDateStr = afterDay+"/"+afterMonth+"/"+afterYear+":"
          +afterHour+":"+afterMin+":"+afterSec;

        SimpleDateFormat format = new SimpleDateFormat(DATE_PATTERN);
        format.setLenient(false);
        mBeforeDate = null;
        mAfterDate = null;

        try {
            mBeforeDate = format.parse(beginDateStr);
        } catch (ParseException e) {
            setErrorMessage("INVALIDBEGINDATE");
            return false;
        }

        try {
            mAfterDate = format.parse(endDateStr);
        } catch (ParseException e) {
            setErrorMessage("INVALIDENDDATE");
            return false;
        }

        if (mAfterDate.before(mBeforeDate)) {
            setErrorMessage("SMALLAFTERDATE");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea heading = createTextArea(mResource.getString(
          mPanelName+"_LABEL_VALIDITY_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(heading, gbc);

        JLabel blank = new JLabel("   ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(blank, gbc);

        JLabel yearLbl = makeJLabel("YEAR");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(yearLbl, gbc);

        JLabel monthLbl = makeJLabel("MONTH");
        add(monthLbl, gbc);

        JLabel dayLbl = makeJLabel("DAY");
        add(dayLbl, gbc);

        JLabel hourLbl = makeJLabel("HOUR");
        add(hourLbl, gbc);

        JLabel minLbl = makeJLabel("MIN");
        add(minLbl, gbc);

        JLabel secLbl = makeJLabel("SEC");
        gbc.gridwidth = gbc.REMAINDER;
        add(secLbl, gbc);

        JLabel beginLbl = makeJLabel("BEGIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(beginLbl, gbc);

        //DateFormat dateFormat = DataFormat.getDateTimeInstance(
        //  DateFormat.FULL,DateFormat.MEDIUM);

        Calendar nowDate = Calendar.getInstance();

        Calendar afterDate = (Calendar)nowDate.clone();
        afterDate.add(Calendar.YEAR, 5);

        mBYear = new JTextField(""+nowDate.get(Calendar.YEAR));
        mBYear.setColumns(4);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mBYear, gbc);

        mBMonth = new JTextField(""+(nowDate.get(Calendar.MONTH)+1));
        mBMonth.setColumns(3);
        add(mBMonth, gbc);

        mBDay = new JTextField(""+nowDate.get(Calendar.DAY_OF_MONTH));
        mBDay.setColumns(3);
        add(mBDay, gbc);

        mBHour = new JTextField("00");
        mBHour.setColumns(3);
        add(mBHour, gbc);

        mBMin = new JTextField("00");
        mBMin.setColumns(3);
        add(mBMin, gbc);

        mBSec = new JTextField("00");
        mBSec.setColumns(3);
        gbc.gridwidth = gbc.REMAINDER;
        add(mBSec, gbc);

        JLabel expireLbl = makeJLabel("EXPIRE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(expireLbl, gbc);

        mEYear = new JTextField(""+afterDate.get(Calendar.YEAR));
        mEYear.setColumns(4);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEYear, gbc);

        mEMonth = new JTextField(""+(afterDate.get(Calendar.MONTH)+1));
        mEMonth.setColumns(3);
        add(mEMonth, gbc);

        mEDay = new JTextField(""+afterDate.get(Calendar.DAY_OF_MONTH));
        mEDay.setColumns(3);
        add(mEDay, gbc);

        mEHour = new JTextField("00");
        mEHour.setColumns(3);
        add(mEHour, gbc);

        mEMin = new JTextField("00");
        mEMin.setColumns(3);
        add(mEMin, gbc);

        mESec = new JTextField("00");
        mESec.setColumns(3);
        gbc.gridwidth = gbc.REMAINDER;
        add(mESec, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy, gbc);
    }
}
