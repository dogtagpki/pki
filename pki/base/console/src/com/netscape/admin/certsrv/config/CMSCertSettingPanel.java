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
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * CA Certificate Setting
 *
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public abstract class CMSCertSettingPanel extends CMSBaseTab {

    /*==========================================================
     * variables
     *==========================================================*/
    protected JLabel _mapper, _publisher;
    protected CMSBaseResourceModel _model;
    protected AdminConnection _admin;
    protected JButton mMapper, mPublisher;

	/*==========================================================
     * constructors
     *==========================================================*/
     
    public CMSCertSettingPanel(String panelName, CMSTabPanel parent) {
        super(panelName, parent);
        _model = parent.getResourceModel();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
     
    /**
     * Actual UI construction
     */
    public void init() {
        _admin = _model.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        
        JPanel mapPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        mapPanel.setLayout(gb2);
        mapPanel.setBorder(makeTitledBorder("MAPPER"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(mapPanel, gbc);
        mCenterPanel.add(mapPanel);
        
        CMSAdminUtil.resetGBC(gbc);
        JLabel mapperLabel = makeJLabel("MAPPER");
        _mapper = new JLabel("");
        mMapper = makeJButton("MAPPER");
        addEntryField(mapPanel, mapperLabel, _mapper, mMapper , gbc);
        
        JPanel  certSetting = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        certSetting.setLayout(gb1);
        certSetting.setBorder(makeTitledBorder("PUBLISHER"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(certSetting, gbc);
        mCenterPanel.add(certSetting);

        CMSAdminUtil.resetGBC(gbc);
        JLabel publisherLabel = makeJLabel("PUBLISHER");
        _publisher = new JLabel("");
        mPublisher = makeJButton("PUBLISHER");
        addEntryField(certSetting, publisherLabel, _publisher, mPublisher, gbc);
    }
    
    /*==========================================================
	 * protected methods
     *==========================================================*/
     
    protected int getIndex(String value, String[] source) {
        for (int i=0; i<source.length; i++) {
            if (value.equals(source[i]))
                return i;
        }
        return -1;
    }
    
    /**
     * Add 3 components in the same row to a panel, assumed to be using
     * GridBagLayout. Customized for the LDAP certificate mappings/publishing
     * UI.
     */
    protected void addEntryField(JPanel panel, JComponent field1, 
      JComponent field2, JComponent field3, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field1, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(field2, gbc);

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field3, gbc );
    }
    
}

