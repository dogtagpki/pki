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

/**
 * Panel Setting CRL Cache
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class CMSCRLCachePanel extends CMSBaseTab {
    
    /*==========================================================
     * variables
     *==========================================================*/    
    private static String PANEL_NAME = "CRLCACHE";

    private JCheckBox mEnableCache;

    private JLabel mCacheFreqLabel;
    private JTextField mCacheFreq;
    private JLabel mCacheFreqMinLabel;

    private JLabel mEnableCacheRecoveryLabel;
    private JCheckBox mEnableCacheRecovery;

    private JLabel mEnableCacheTestingLabel;
    private JCheckBox mEnableCacheTesting;

    private Color mActiveColor;
    private AdminConnection _admin;
    private CMSBaseResourceModel _model;
    private CMSTabPanel mParent;
    private String mId = null;
    private static final String HELPINDEX =
        "configuration-ca-ldappublish-crl-help";
    private CMSCRLFormatPanel mCRLFormatPanel = null;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCRLCachePanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        _model = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public CMSCRLCachePanel(CMSTabPanel parent, String id) {
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
        Debug.println("CRLCachePanel: init()");
        _admin = _model.getServerInfo().getAdmin();
        
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);
        

        //cache panel
        JPanel cachePanel = new JPanel();
        cachePanel.setBorder(makeTitledBorder("CACHE"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(cachePanel, gbc);
        mCenterPanel.add(cachePanel);

        GridBagLayout gb3 = new GridBagLayout();
        cachePanel.setLayout(gb3);


        // enable cache
        CMSAdminUtil.resetGBC(gbc);
        JLabel enableCacheLabel = makeJLabel("CACHE");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        cachePanel.add(enableCacheLabel, gbc);

        mEnableCache = makeJCheckBox();
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        cachePanel.add(mEnableCache, gbc);


        // how often to save cache
        CMSAdminUtil.resetGBC(gbc);
        mCacheFreqLabel = makeJLabel("INTERVAL");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        cachePanel.add(mCacheFreqLabel, gbc);

        mCacheFreq = makeJTextField(5);
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        cachePanel.add(mCacheFreq, gbc);
        mActiveColor = mCacheFreq.getBackground();

        mCacheFreqMinLabel = makeJLabel("MINUTES");
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        cachePanel.add(mCacheFreqMinLabel, gbc);


        // enable cache recovery
        CMSAdminUtil.resetGBC(gbc);
        mEnableCacheRecoveryLabel = makeJLabel("RECOVERY");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        cachePanel.add(mEnableCacheRecoveryLabel, gbc );

        mEnableCacheRecovery = makeJCheckBox();
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        cachePanel.add(mEnableCacheRecovery, gbc);

        // enable cache testing
        CMSAdminUtil.resetGBC(gbc);
        mEnableCacheTestingLabel = makeJLabel("TEST");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        cachePanel.add(mEnableCacheTestingLabel, gbc );

        mEnableCacheTesting = makeJCheckBox();
        gbc.anchor = gbc.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        cachePanel.add(mEnableCacheTesting, gbc);

        int nTabs = mParent.mTabbedPane.getTabCount();
        for (int i = 0; i < nTabs; i++) {
            Object p = mParent.mTabbedPane.getComponentAt(i);
            if (p instanceof CMSCRLFormatPanel) {
                mCRLFormatPanel = (CMSCRLFormatPanel)p;
            }
        }

        refresh();
    }

    public void refresh() {
        _model.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_ENABLE_CACHE, "");
        nvps.put(Constants.PR_CACHE_FREQ, "");
        nvps.put(Constants.PR_CACHE_RECOVERY, "");
        nvps.put(Constants.PR_CACHE_TESTING, "");

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
        String signingAlg = "";
        for (String name : nvps.keySet()) {
            String value = nvps.get(name).trim();
            if (name.equals(Constants.PR_ENABLE_CACHE)) {
                mEnableCache.setSelected(getBoolean(value, true));
            } else if (name.equals(Constants.PR_CACHE_FREQ)) {
                mCacheFreq.setText(value);
            } else if (name.equals(Constants.PR_CACHE_RECOVERY)) {
                mEnableCacheRecovery.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_CACHE_TESTING)) {
                mEnableCacheTesting.setSelected(getBoolean(value));
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

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        String cacheFreq = "";
        int iCacheFreq = 0;

        NameValuePairs nvps = new NameValuePairs();


        if (mEnableCache.isSelected())
            nvps.put(Constants.PR_ENABLE_CACHE, Constants.TRUE);
        else
            nvps.put(Constants.PR_ENABLE_CACHE, Constants.FALSE);

        cacheFreq = mCacheFreq.getText().trim();
        if (cacheFreq.equals("")) {
            showMessageDialog("BLANKFIELD");
            return false;
        }
        try {
            iCacheFreq = Integer.parseInt(cacheFreq);
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }
        if (iCacheFreq < 0) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }
        nvps.put(Constants.PR_CACHE_FREQ, cacheFreq);


        if (mEnableCacheRecovery.isSelected())
            nvps.put(Constants.PR_CACHE_RECOVERY, Constants.TRUE);
        else
            nvps.put(Constants.PR_CACHE_RECOVERY, Constants.FALSE);

        if (mEnableCacheTesting.isSelected())
            nvps.put(Constants.PR_CACHE_TESTING, Constants.TRUE);
        else
            nvps.put(Constants.PR_CACHE_TESTING, Constants.FALSE);

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
        refresh();
        return true;
    }    

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mEnableCache)) {
            enableFields();
        }
        super.actionPerformed(e);
    }

    private void enableFields() {
        boolean enable = mEnableCache.isSelected();
        Color color = (enable)? mActiveColor: getBackground();
        mCRLFormatPanel.setCacheEnabled(enable);

        mCacheFreqLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mCacheFreqLabel);

        CMSAdminUtil.enableJTextField(mCacheFreq, enable, color);

        mCacheFreqMinLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mCacheFreqMinLabel);

        mEnableCacheRecoveryLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mEnableCacheRecoveryLabel);

        mEnableCacheRecovery.setEnabled(enable);
        CMSAdminUtil.repaintComp(mEnableCacheRecovery);

        mEnableCacheTestingLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(mEnableCacheTestingLabel);

        mEnableCacheTesting.setEnabled(enable);
        CMSAdminUtil.repaintComp(mEnableCacheTesting);
    }
}

