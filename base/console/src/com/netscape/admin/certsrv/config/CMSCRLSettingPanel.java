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

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * CRL Publishing Setting Panel
 *
 * @author Andrew Wnuk
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSCRLSettingPanel extends CMSBaseTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CRLSETTING";

    private JCheckBox mEnableCRL;
    private JLabel mCRLGenLabel;
    private JTextField mCRLGen;
    private JLabel mDeltaGenLabel;

    private JLabel mExtendNextUpdateLabel;
    private JCheckBox mExtendNextUpdate;

    private JCheckBox mAlways;
    private JCheckBox mDaily;
    private JTextField mDailyAt;
    private JCheckBox mEnableFreq;
    private JTextField mFrequency;
    private JLabel mMinLabel;
    private JLabel mGracePeriodLabel;
    private JTextField mGracePeriod;
    private JLabel mGracePeriodMinLabel;
    private JLabel mNextAsThisUpdateExtensionLabel;
    private JTextField mNextAsThisUpdateExtension;
    private JLabel mNextAsThisUpdateExtensionMinLabel;

    private Color mActiveColor;
    private AdminConnection _admin;
    private CMSBaseResourceModel _model;
    private CMSTabPanel mParent;
    private String mId = null;
    private static final String HELPINDEX =
        "configuration-ca-ldappublish-crl-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCRLSettingPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        _model = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public CMSCRLSettingPanel(CMSTabPanel parent, String id) {
        super(PANEL_NAME, parent);
        _model = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
        mId = id;
    }

    /*==========================================================
     * public methods
     *==========================================================*/
    public void init() {
        Debug.println("CRLSettingPanel: init()");
        _admin = _model.getServerInfo().getAdmin();

        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);


        //schema panel
        JPanel schemaPanel = new JPanel();
        schemaPanel.setBorder(makeTitledBorder("SCHEMA"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gb.setConstraints(schemaPanel, gbc);
        mCenterPanel.add(schemaPanel);

        GridBagLayout gb4 = new GridBagLayout();
        schemaPanel.setLayout(gb4);


        // enable CRL generation
        CMSAdminUtil.resetGBC(gbc);
        JLabel enableCRLLabel = makeJLabel("CRL");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        schemaPanel.add(enableCRLLabel, gbc );

        mEnableCRL = makeJCheckBox();
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        schemaPanel.add(mEnableCRL, gbc);


        // generate full CRL every X deltas
        CMSAdminUtil.resetGBC(gbc);
        mCRLGenLabel = makeJLabel("GENERATION");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        schemaPanel.add(mCRLGenLabel, gbc );

        mCRLGen = makeJTextField(5);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        schemaPanel.add(mCRLGen, gbc);
        mActiveColor = mCRLGen.getBackground();

        mDeltaGenLabel = makeJLabel("DELTAS");
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        schemaPanel.add(mDeltaGenLabel, gbc);


        // Extend next update time
        CMSAdminUtil.resetGBC(gbc);
        mExtendNextUpdateLabel = makeJLabel("NEXTTIME");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        schemaPanel.add(mExtendNextUpdateLabel, gbc );

        mExtendNextUpdate = makeJCheckBox();
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        schemaPanel.add(mExtendNextUpdate, gbc);


        //frequency panel
        JPanel freqPanel = new JPanel();
        freqPanel.setBorder(makeTitledBorder("FREQ"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(freqPanel, gbc);
        mCenterPanel.add(freqPanel);

        //add components
        GridBagLayout gb2 = new GridBagLayout();
        freqPanel.setLayout(gb2);


        // update every time
        CMSAdminUtil.resetGBC(gbc);
        mAlways = makeJCheckBox("ALWAYS");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,COMPONENT_SPACE);
        freqPanel.add(mAlways, gbc);


        // update at specified time
        CMSAdminUtil.resetGBC(gbc);
        mDaily = makeJCheckBox("DAILY");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        freqPanel.add(mDaily, gbc);

        mDailyAt = makeJTextField(30);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        freqPanel.add(mDailyAt, gbc);


        // update by time interval
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        mEnableFreq = makeJCheckBox("FREQ");
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        freqPanel.add(mEnableFreq, gbc);

        mFrequency = makeJTextField(5);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        freqPanel.add(mFrequency, gbc);

        mMinLabel = makeJLabel("MINUTES");
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        freqPanel.add(mMinLabel, gbc);


        // next update grace period
        CMSAdminUtil.resetGBC(gbc);
        mGracePeriodLabel = makeJLabel("GRACEPERIOD");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        // gbc.gridx = 2;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        freqPanel.add(mGracePeriodLabel, gbc);

        mGracePeriod = makeJTextField(5);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        freqPanel.add(mGracePeriod, gbc);

        mGracePeriodMinLabel = makeJLabel("MINUTES");
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        freqPanel.add(mGracePeriodMinLabel, gbc);

        // next update as this update extension
        CMSAdminUtil.resetGBC(gbc);
        mNextAsThisUpdateExtensionLabel = makeJLabel("NEXTASTHISEXTENSION");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        // gbc.gridx = 2;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        freqPanel.add(mNextAsThisUpdateExtensionLabel, gbc);

        mNextAsThisUpdateExtension = makeJTextField(5);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        freqPanel.add(mNextAsThisUpdateExtension, gbc);

        mNextAsThisUpdateExtensionMinLabel = makeJLabel("MINUTES");
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        freqPanel.add(mNextAsThisUpdateExtensionMinLabel, gbc);

        refresh();
    }

    public void refresh() {
        _model.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_ENABLE_CRL, "");
        nvps.put(Constants.PR_UPDATE_SCHEMA, "");
        nvps.put(Constants.PR_EXTENDED_NEXT_UPDATE, "");
        nvps.put(Constants.PR_UPDATE_ALWAYS, "");
        nvps.put(Constants.PR_ENABLE_DAILY, "");
        nvps.put(Constants.PR_DAILY_UPDATES, "");
        nvps.put(Constants.PR_ENABLE_FREQ, "");
        nvps.put(Constants.PR_UPDATE_FREQ, "");
        nvps.put(Constants.PR_GRACE_PERIOD, "");
        nvps.put(Constants.PR_NEXT_AS_THIS_EXTENSION, "");

        try {
            NameValuePairs val = null;
            if (mId != null && mId.length() > 0) {
                val = _admin.read(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                                  mId, nvps);
            } else {
                val = _admin.read(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                                  Constants.RS_ID_CONFIG, nvps);
            }

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
        }
        _model.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();

        enableFields();
    }

    public void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String value = nvps.get(name).trim();
            if (name.equals(Constants.PR_ENABLE_CRL)) {
                mEnableCRL.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_UPDATE_SCHEMA)) {
                mCRLGen.setText(value);
            } else if (name.equals(Constants.PR_EXTENDED_NEXT_UPDATE)) {
                mExtendNextUpdate.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_UPDATE_ALWAYS)) {
                mAlways.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_ENABLE_DAILY)) {
                mDaily.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_DAILY_UPDATES)) {
                mDailyAt.setText(value);
            } else if (name.equals(Constants.PR_ENABLE_FREQ)) {
                mEnableFreq.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_UPDATE_FREQ)) {
                mFrequency.setText(value);
            } else if (name.equals(Constants.PR_GRACE_PERIOD)) {
                mGracePeriod.setText(value);
            } else if (name.equals(Constants.PR_NEXT_AS_THIS_EXTENSION)) {
                mNextAsThisUpdateExtension.setText(value);
            }
        }
    }

    public boolean getBoolean(String val) {
        if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public boolean getBoolean(String val, boolean defaultValue) {
        if (val.equals(Constants.TRUE))
            return true;
        else if (val.equals(Constants.FALSE))
            return false;
        else
            return defaultValue;
    }

    private int checkTime(String time) {
        String digits = "0123456789";
        int len = time.length();
        if (len < 3 || len > 5) return -1;
        int s = time.indexOf(':');
        if (s < 0 || s > 2 || (len - s) != 3) return -1;

        int h = 0;
        for (int i = 0; i < s; i++) {
            h *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0) return -1;
            h += k;
        }
        if (h > 23)  return -1;

        int m = 0;
        for (int i = s+1; i < len; i++) {
            m *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0) return -1;
            m += k;
        }
        if (m > 59)  return -1;

        return ((h * 60) + m);
    }

    private String trimList(String list) {
        String trimmed = "";

        StringTokenizer days = new StringTokenizer(list, ";", true);
        while (days.hasMoreTokens()) {
            String dayList = days.nextToken().trim();
            if (dayList == null || dayList.length() == 0) continue;
            if (dayList.equals(";")) {
                trimmed += dayList;
                continue;
            }
            StringTokenizer elements = new StringTokenizer(dayList, ",", true);
            int n = 0;
            while (elements.hasMoreTokens()) {
                String element = elements.nextToken().trim();
                if (element == null || element.length() == 0) return null;
                if (element.equals(",") && n % 2 == 0) return null;
                trimmed += element;
                n++;
            }
            if (n % 2 == 0) return null;
        }
        return trimmed;
    }

    private Vector checkTimeList(String list) {
        if (list == null || list.length() == 0) return null;
        if (list.charAt(0) == ',' || list.charAt(list.length()-1) == ',') return null;

        Vector listedTimes = new Vector();

        StringTokenizer days = new StringTokenizer(list, ";");
        while (days.hasMoreTokens()) {
            String dayList = days.nextToken().trim();
            if (dayList == null || dayList.length() == 0) continue;
            int t0 = -1;
            StringTokenizer times = new StringTokenizer(dayList, ",");
            while (times.hasMoreTokens()) {
                String time = times.nextToken();
                if (time.charAt(0) == '*') time = time.substring(1);
                int t = checkTime(time);
                if (t < 0) {
                    return null;
                } else {
                    if (t > t0) {
                        listedTimes.addElement(new Integer(t));
                        t0 = t;
                    } else {
                        return null;
                    }
                }
            }
        }
        return listedTimes;
    }


    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        String timeList = trimList(mDailyAt.getText());

        if (mEnableCRL.isSelected()) {
            if (!mAlways.isSelected() && !mDaily.isSelected() &&
                !mEnableFreq.isSelected()) {
                showMessageDialog("UPDATES");
                return false;
            }

            if (mCRLGen.getText().trim().equals("")) {
                showMessageDialog("BLANKSCHEMA");
                return false;
            }
            try {
                int num = Integer.parseInt(mCRLGen.getText().trim());
                if (num < 1) {
                    showMessageDialog("SCHEMANUMBER");
                    return false;
                }
            } catch (NumberFormatException e) {
                showMessageDialog("SCHEMANUMBER");
                return false;
            }

            Vector daily = null;
            if (mDaily.isSelected()) {
                if (mDailyAt.getText().trim().equals("")) {
                    showMessageDialog("BLANKDAILY");
                    return false;
                }
                daily = checkTimeList(timeList);
                if (daily == null) {
                    showMessageDialog("DAILYFORMAT");
                    return false;
                }
            }

            if (mEnableFreq.isSelected()) {
                if (mFrequency.getText().trim().equals("")) {
                    showMessageDialog("BLANKFREQ");
                    return false;
                }
                int freq = 0;
                try {
                    freq = Integer.parseInt(mFrequency.getText().trim());
                    if (freq < 1) {
                        showMessageDialog("FREQNUMBER");
                        return false;
                    }
                } catch (NumberFormatException e) {
                    showMessageDialog("FREQNUMBER");
                    return false;
                }
                if (mDaily.isSelected() && daily != null && daily.size() > 1) {
                    showMessageDialog("DAILYFORMAT");
                    return false;
                }
                if (mDaily.isSelected() && daily != null && daily.size() == 1 &&
                    (freq >= 1440 ||
                     freq + ((Integer)(daily.elementAt(0))).intValue() >= 1440)) {
                    showMessageDialog("INTERVALTOBIG");
                    return false;
                }
            }

            if (mGracePeriod.getText().trim().equals("")) {
                showMessageDialog("BLANKGRACE");
                return false;
            }
            try {
                int grace = Integer.parseInt(mGracePeriod.getText().trim());
                if (grace < 0) {
                    showMessageDialog("GRACENUMBER");
                    return false;
                }
            } catch (NumberFormatException e) {
                showMessageDialog("GRACENUMBER");
                return false;
            }

            if (mNextAsThisUpdateExtension.getText().trim().equals("")) {
                showMessageDialog("BLANKNEXTASTHISEXTENSION");
                return false;
            }
            try {
                int nextAsThisUpdateExtension = Integer.parseInt(mNextAsThisUpdateExtension.getText().trim());
                if (nextAsThisUpdateExtension < 0) {
                    showMessageDialog("NEXTASTHISEXTENSIONNUMBER");
                    return false;
                }
            } catch (NumberFormatException e) {
                showMessageDialog("NEXTASTHISEXTENSIONNUMBER");
                return false;
            }
        }

        NameValuePairs nvps = new NameValuePairs();

        if (mEnableCRL.isSelected())
            nvps.put(Constants.PR_ENABLE_CRL, Constants.TRUE);
        else
            nvps.put(Constants.PR_ENABLE_CRL, Constants.FALSE);

        nvps.put(Constants.PR_UPDATE_SCHEMA, mCRLGen.getText().trim());

        if (mExtendNextUpdate.isSelected())
            nvps.put(Constants.PR_EXTENDED_NEXT_UPDATE, Constants.TRUE);
        else
            nvps.put(Constants.PR_EXTENDED_NEXT_UPDATE, Constants.FALSE);

        if (mAlways.isSelected())
            nvps.put(Constants.PR_UPDATE_ALWAYS, Constants.TRUE);
        else
            nvps.put(Constants.PR_UPDATE_ALWAYS, Constants.FALSE);

        if (mDaily.isSelected())
            nvps.put(Constants.PR_ENABLE_DAILY, Constants.TRUE);
        else
            nvps.put(Constants.PR_ENABLE_DAILY, Constants.FALSE);

        if (timeList != null)
            nvps.put(Constants.PR_DAILY_UPDATES, timeList);
        else
            nvps.put(Constants.PR_DAILY_UPDATES, mDailyAt.getText().trim());


        if (mEnableFreq.isSelected())
            nvps.put(Constants.PR_ENABLE_FREQ, Constants.TRUE);
        else
            nvps.put(Constants.PR_ENABLE_FREQ, Constants.FALSE);

        nvps.put(Constants.PR_UPDATE_FREQ, mFrequency.getText().trim());

        nvps.put(Constants.PR_GRACE_PERIOD, mGracePeriod.getText().trim());

        nvps.put(Constants.PR_NEXT_AS_THIS_EXTENSION, mNextAsThisUpdateExtension.getText().trim());

        _model.progressStart();

        try {
            if (mId != null && mId.length() > 0) {
                _admin.modify(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                              mId, nvps);
            } else {
                _admin.modify(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                              Constants.RS_ID_CONFIG, nvps);
            }
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
            return false;
        }

        _model.progressStop();
        clearDirtyFlag();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        Debug.println("CRLSettingPanel: resetCallback()");
        refresh();
        return true;
    }

    public void actionPerformed(ActionEvent e) {
        Debug.println("CRLSettingPanel: actionPerformed()");
        if (e.getSource().equals(mEnableCRL)) {
            enableFields();
        }

        if (e.getSource().equals(mDaily)) {
            if (mDaily.isSelected()) {
                CMSAdminUtil.enableJTextField(mDailyAt, true, mActiveColor);
                CMSAdminUtil.enableJTextField(mGracePeriod, true, mActiveColor);
                mGracePeriodLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mGracePeriodLabel);
                mGracePeriodMinLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mGracePeriodMinLabel);
                CMSAdminUtil.enableJTextField(mNextAsThisUpdateExtension, true, mActiveColor);
                mNextAsThisUpdateExtensionLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionLabel);
                mNextAsThisUpdateExtensionMinLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionMinLabel);
            } else {
                CMSAdminUtil.enableJTextField(mDailyAt, false, getBackground());
                if (!mEnableFreq.isSelected()) {
                    CMSAdminUtil.enableJTextField(mGracePeriod, false, getBackground());
                    mGracePeriodLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mGracePeriodLabel);
                    mGracePeriodMinLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mGracePeriodMinLabel);
                    CMSAdminUtil.enableJTextField(mNextAsThisUpdateExtension, false, getBackground());
                    mNextAsThisUpdateExtensionLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionLabel);
                    mNextAsThisUpdateExtensionMinLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionMinLabel);
                }
            }
        }
        if (e.getSource().equals(mEnableFreq)) {
            if (mEnableFreq.isSelected()) {
                CMSAdminUtil.enableJTextField(mFrequency, true, mActiveColor);
                mMinLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mMinLabel);
                CMSAdminUtil.enableJTextField(mGracePeriod, true, mActiveColor);
                mGracePeriodLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mGracePeriodLabel);
                mGracePeriodMinLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mGracePeriodMinLabel);
                CMSAdminUtil.enableJTextField(mNextAsThisUpdateExtension, true, mActiveColor);
                mNextAsThisUpdateExtensionLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionLabel);
                mNextAsThisUpdateExtensionMinLabel.setEnabled(true);
                CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionMinLabel);
            } else {
                CMSAdminUtil.enableJTextField(mFrequency, false, getBackground());
                mMinLabel.setEnabled(false);
                CMSAdminUtil.repaintComp(mMinLabel);
                if (!mDaily.isSelected()) {
                    CMSAdminUtil.enableJTextField(mGracePeriod, false, getBackground());
                    mGracePeriodLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mGracePeriodLabel);
                    mGracePeriodMinLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mGracePeriodMinLabel);
                    CMSAdminUtil.enableJTextField(mNextAsThisUpdateExtension, false, getBackground());
                    mNextAsThisUpdateExtensionLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionLabel);
                    mNextAsThisUpdateExtensionMinLabel.setEnabled(false);
                    CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionMinLabel);
                }
            }
        }

        super.actionPerformed(e);
    }

    private void enableFields() {
        boolean enable = mEnableCRL.isSelected();
        Color color = (enable)? mActiveColor: getBackground();

        CMSAdminUtil.enableJTextField(mCRLGen, enable, color);
        mCRLGenLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mCRLGenLabel);
        mDeltaGenLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mDeltaGenLabel);

        mExtendNextUpdateLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mExtendNextUpdateLabel);
        mExtendNextUpdate.setEnabled(enable);
        CMSAdminUtil.repaintComp(mExtendNextUpdate);

        mAlways.setEnabled(enable);
        CMSAdminUtil.repaintComp(mAlways);

        mDaily.setEnabled(enable);
        CMSAdminUtil.repaintComp(mDaily);

        boolean enable1 = enable && mDaily.isSelected();
        Color color1 = (enable1)? mActiveColor: getBackground();
        CMSAdminUtil.enableJTextField(mDailyAt, enable1, color1);

        mEnableFreq.setEnabled(enable);
        CMSAdminUtil.repaintComp(mEnableFreq);

        boolean enable2 = enable && mEnableFreq.isSelected();
        Color color2 = (enable2)? mActiveColor: getBackground();
        CMSAdminUtil.enableJTextField(mFrequency, enable2, color2);
        mMinLabel.setEnabled(enable2);
        CMSAdminUtil.repaintComp(mMinLabel);

        boolean enable3 = enable1 || enable2;
        Color color3 = (enable3)? mActiveColor: getBackground();
        CMSAdminUtil.enableJTextField(mGracePeriod, enable3, color3);
        mGracePeriodLabel.setEnabled(enable3);
        CMSAdminUtil.repaintComp(mGracePeriodLabel);
        mGracePeriodMinLabel.setEnabled(enable3);
        CMSAdminUtil.repaintComp(mGracePeriodMinLabel);
        CMSAdminUtil.enableJTextField(mNextAsThisUpdateExtension, enable3, color3);
        mNextAsThisUpdateExtensionLabel.setEnabled(enable3);
        CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionLabel);
        mNextAsThisUpdateExtensionMinLabel.setEnabled(enable3);
        CMSAdminUtil.repaintComp(mNextAsThisUpdateExtensionMinLabel);
    }
}

