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
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Certificate wizard page
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class WBaseCertRequestPage extends WizardBasePanel {
    protected JButton mCopy;
    protected JRadioButton mEmailBtn;
    protected JRadioButton mURLBtn;
    protected JRadioButton mManualBtn;
    protected JTextArea mText;
    protected JTextField mURLText;
    protected JTextField mEmailText, mContactEmailTxt, mNameTxt, mContactPhoneTxt;
    protected JLabel mContactPhoneLbl, mContactEmailLbl, mNameLbl;
    protected JTextArea mContactText;
    
    public WBaseCertRequestPage(String panelName) {
        super(panelName);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        JTextArea unixDesc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CERTREQUESTWIZARD_TEXT_UNIXDESC_LABEL"), 80), 3, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(unixDesc, gbc);

        JTextArea ntDesc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CERTREQUESTWIZARD_TEXT_NTDESC_LABEL"), 80), 3, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(ntDesc, gbc);
*/

        JLabel desc = makeJLabel("DESC");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mManualBtn = makeJRadioButton("MANUAL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mManualBtn, gbc);

        mText = new JTextArea(null, null, 0, 0);
        //mText.setLineWrap(true);
        //mText.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(mText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 20));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.BOTH;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(scrollPane, gbc);

        mCopy = makeJButton("COPY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(mCopy, gbc);

        mEmailBtn = makeJRadioButton("EMAIL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEmailBtn, gbc);

        mEmailText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, COMPONENT_SPACE); 
        gbc.gridwidth = gbc.REMAINDER;
        add(mEmailText, gbc);
       
        mURLBtn = makeJRadioButton("URL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mURLBtn, gbc);

        mURLText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mURLText, gbc);
       
        ButtonGroup methodGroup = new ButtonGroup();
        methodGroup.add(mEmailBtn);
        methodGroup.add(mURLBtn);
        methodGroup.add(mManualBtn);

        mContactText = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "COPYCERTREQUESTWIZARD_TEXT_CONTACT_LABEL"), 80), 2, 80);
        mContactText.setBackground(getBackground());
        mContactText.setEditable(false);
        mContactText.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;  
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mContactText, gbc);

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);
        //panel.setBorder(new EtchedBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        add(panel, gbc);
  
        mNameLbl = makeJLabel("NAME");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(mNameLbl, gbc);

        mNameTxt = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        panel.add(mNameTxt, gbc);

        mContactEmailLbl = makeJLabel("EMAILADDRESS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(mContactEmailLbl, gbc);

        mContactEmailTxt = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        panel.add(mContactEmailTxt, gbc);
       
        mContactPhoneLbl = makeJLabel("PHONE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(mContactPhoneLbl, gbc);

        mContactPhoneTxt = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        panel.add(mContactPhoneTxt, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        panel.add(dummy, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent event) {
        if (event.getSource().equals(mCopy)) {
            mText.copy();
        }
    }
}
