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

import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;

/**
 * Base Log Panel
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public abstract class CMSBaseLogPanel extends CMSBaseTab {
    /*==========================================================
     * variables
     *==========================================================*/
	protected JCheckBox activateLog;

	protected JComboBox mlogFQC, mLogLevel, mNTLogLevel;
	protected JTextField mlogMaxSizText, mlogBufSizText, mEventSourceText;
	protected Color mActiveColor;

	protected Object mselectedItem;
	protected String mlogMaxSizTextData, mlogBufSizTextData;
    protected CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    protected int mLevel, mNTLevel;
    protected int mFrequency;
    protected String mSource;

    protected JLabel mMaxLabel, mNTLogLevelLbl;
    protected JLabel mBufferLabel, mEventSourceLbl;
    protected JCheckBox mActivateNTLog;
    protected boolean mIsNT;

    protected final static int YEAR = 31536000;
    protected final static int MONTH = 2592000;
    protected final static int WEEK = 604800;
    protected final static int DAY = 86400;
    protected final static int HOUR = 3600;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseLogPanel(String panelName, CMSTabPanel parent) {
        super(panelName, parent);
        mModel = parent.getResourceModel();
    }
    
    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual Instantiation of the UI components
     */
    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
		GridBagLayout gb = new GridBagLayout();
	    GridBagConstraints gbc = new GridBagConstraints();
		CMSAdminUtil.resetGBC(gbc);
		mCenterPanel.setLayout(gb);

		//=== Activate Radio Button ===
		activateLog = makeJCheckBox("ACTIVATE");
		CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTHWEST;
		gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
		gb.setConstraints(activateLog, gbc);
		mCenterPanel.add(activateLog);

		// use a lined border later...titled for now
        JPanel logInfo = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        logInfo.setLayout(gb1);
        logInfo.setBorder(makeTitledBorder("LOGATTRIBUTE"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        if (!mIsNT)
            gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(logInfo, gbc);
        mCenterPanel.add(logInfo);

		// Log Rotation Frequency
		CMSAdminUtil.resetGBC(gbc);
		JLabel logFQC = makeJLabel("LOGFQC");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        logInfo.add(logFQC, gbc);
		
		mlogFQC = makeJComboBox("LOGFQC");
        gbc.anchor = gbc.WEST;
        logInfo.add(mlogFQC, gbc);

        JLabel dummyFQC = new JLabel();
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        logInfo.add(dummyFQC, gbc);
        
		// Log File Maximum Size
        CMSAdminUtil.resetGBC(gbc);
        JLabel logMaxSiz = makeJLabel("LOGMAXSIZ");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        logInfo.add(logMaxSiz, gbc);

        mlogMaxSizText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 0.007;
        gbc.fill = gbc.HORIZONTAL;
        logInfo.add(mlogMaxSizText, gbc);
        mActiveColor = mlogMaxSizText.getBackground();
   
        mMaxLabel = makeJLabel("SIZEUNIT");
        gbc.weightx = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, COMPONENT_SPACE);
        logInfo.add(mMaxLabel, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        logInfo.add(dummy, gbc);

		// Log File Buffer Size
        CMSAdminUtil.resetGBC(gbc);
        JLabel logBufSiz = makeJLabel("LOGBUFSIZ");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        logInfo.add(logBufSiz, gbc);

        mlogBufSizText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 0.007;
        gbc.fill = gbc.HORIZONTAL;
        logInfo.add(mlogBufSizText, gbc);

        mBufferLabel = makeJLabel("SIZEUNIT");
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.fill = gbc.NONE;
        logInfo.add(mBufferLabel, gbc);

        JLabel dummy1 = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        logInfo.add(dummy1, gbc);

        // Log Level
        CMSAdminUtil.resetGBC(gbc);
        JLabel logLevel = makeJLabel("LOGLEVEL");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        logInfo.add(logLevel, gbc);

        mLogLevel = makeJComboBox("LOGLEVEL");
        gbc.anchor = gbc.WEST;
        logInfo.add(mLogLevel, gbc);

        JLabel dummy2 = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        logInfo.add(dummy2, gbc);

        if (mIsNT)
            addNTEventLog();
	}

    private void addNTEventLog() {
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mActivateNTLog = makeJCheckBox("ACTIVATENTLOG");
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        mCenterPanel.add(mActivateNTLog, gbc);

        JPanel NTLogInfo = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        NTLogInfo.setLayout(gb1);
        NTLogInfo.setBorder(makeTitledBorder("NTLOGATTRIBUTE"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        mCenterPanel.add(NTLogInfo, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEventSourceLbl = makeJLabel("EVENTSOURCE");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        NTLogInfo.add(mEventSourceLbl, gbc);

        mEventSourceText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 0.007;
        gbc.fill = gbc.HORIZONTAL;
        NTLogInfo.add(mEventSourceText, gbc);

        JLabel dummy1 = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        NTLogInfo.add(dummy1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mNTLogLevelLbl = makeJLabel("LOGLEVEL");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        NTLogInfo.add(mNTLogLevelLbl, gbc);

        mNTLogLevel = makeJComboBox("LOGLEVEL");
        gbc.anchor = gbc.WEST;
        NTLogInfo.add(mNTLogLevel, gbc);

        JLabel dummy2 = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        NTLogInfo.add(dummy2, gbc);
    }

	/*==========================================================
	 * private methods
     *==========================================================*/

    //enable/disable section
    protected void setSection(boolean flag) {
		mlogFQC.setEnabled(flag);
		mLogLevel.setEnabled(flag);
        mlogMaxSizText.setEditable(flag);
        mlogBufSizText.setEditable(flag);
        if (flag) {
			mlogFQC.setBackground(mActiveColor);
            mLogLevel.setBackground(mActiveColor);
            mlogMaxSizText.setBackground(mActiveColor);
            mlogBufSizText.setBackground(mActiveColor);
        } else {
            mLogLevel.setBackground(getBackground());
			mlogFQC.setBackground(getBackground());
            mlogMaxSizText.setBackground(getBackground());
            mlogBufSizText.setBackground(getBackground());
        }
		mlogFQC.repaint();
		mlogMaxSizText.repaint();
		mlogBufSizText.repaint();
    }

    protected void setNTSection(boolean flag, Color color) {
        mNTLogLevel.setEnabled(flag);
        mEventSourceText.setEnabled(flag);
        mEventSourceText.setEditable(flag);
        mEventSourceText.setBackground(color);
        CMSAdminUtil.repaintComp(mNTLogLevel);
        CMSAdminUtil.repaintComp(mEventSourceText);
    }

    //update component data
    protected void setValues() {
        if (activateLog.isSelected()) {
            setSection(true);
		} else {
		    setSection(false);
		}
		mlogFQC.setSelectedIndex(mFrequency);
        mlogMaxSizText.setText(mlogMaxSizTextData);
	    mlogBufSizText.setText(mlogBufSizTextData);
        mLogLevel.setSelectedIndex(mLevel);       

        if (mIsNT) {
            if (mActivateNTLog.isSelected()) {
                setNTSection(true, mActiveColor);
            } else {
                setNTSection(false, getBackground());
            }
            mEventSourceText.setText(mSource);
            mNTLogLevel.setSelectedIndex(mNTLevel);
        }
    }

    protected int getRollOverTime(int index) {
        if (index == 0)
            return HOUR;
        else if (index == 1)
            return DAY;
        else if (index == 2)
            return WEEK;
        else if (index == 3)
            return MONTH;
        return YEAR;
    }

    protected int getRollOverIndex(int val) {
        if (val >= YEAR)
            return 4;
        else if (val >= MONTH)
            return 3;
        else if (val >= WEEK)
            return 2;
        else if (val >= DAY)
            return 1;
        return 0;
    }

	/*==========================================================
	 * EVENT HANDLER METHODS
     *==========================================================*/     
     
    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
		super.actionPerformed(e);
        if (e.getSource().equals(activateLog) ||
          e.getSource().equals(mActivateNTLog)) {
            setValues();
		}
	}
}
