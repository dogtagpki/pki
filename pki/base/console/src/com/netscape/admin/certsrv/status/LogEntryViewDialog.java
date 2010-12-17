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
package com.netscape.admin.certsrv.status;

import com.netscape.admin.certsrv.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import javax.swing.table.*;
import com.netscape.certsrv.common.*;

/**
 * Policy Implementation Information viewer
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class LogEntryViewDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String  PREFIX = "LOGENTRYVIEWDIALOG";

    private JFrame mParentFrame;
    private ResourceBundle mResource;
    private JTextArea mTextArea;
    private JLabel mSource, mLevel, mDate, mTime;

    private JButton mOK;

    /*==========================================================
     * constructors
     *==========================================================*/
    public LogEntryViewDialog(JFrame parent) {
        super(parent,true);
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(600, 400);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * show the windows
     */
    public void showDialog(String source, String level,
                           String date, String time, String desc) {
        //initialize and setup
        mSource.setText(source);
        mLevel.setText(level);
        mDate.setText(date);
        mTime.setText(time);
        mTextArea.setText(desc);
        mTextArea.setCaretPosition(0);
        this.show();
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	public void actionPerformed(ActionEvent evt) {
	    if (evt.getSource().equals(mOK)) {
	        this.hide();
	    }
	}

    /*==========================================================
	 * private methods
     *==========================================================*/
    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
        gb.setConstraints(content, gbc);
		center.add(content);

		//action panel
		JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.gridheight = gbc.REMAINDER;
		gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
		center.add(action);

		getContentPane().add("Center",center);
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        Dimension d = mOK.getMinimumSize();
        if (d.width < CMSAdminUtil.DEFAULT_BUTTON_SIZE) {
            d.width = CMSAdminUtil.DEFAULT_BUTTON_SIZE;
            mOK.setMinimumSize(d);
        }
		JButton[] buttons = {mOK};
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "SOURCE", null);
        mSource = new JLabel();
        CMSAdminUtil.addEntryField(content, label1, mSource, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "LEVEL", null);
        mLevel = new JLabel();
        CMSAdminUtil.addEntryField(content, label2, mLevel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "DATE", null);
        mDate = new JLabel();
        CMSAdminUtil.addEntryField(content, label3, mDate, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label4 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "TIME", null);
        mTime = new JLabel();
        CMSAdminUtil.addEntryField(content, label4, mTime, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label5 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "DESC", null);
        label5.setHorizontalAlignment(JLabel.RIGHT);
        gbc.anchor = gbc.NORTHEAST;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,0,0);
        gb3.setConstraints(label5, gbc);
        content.add(label5);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",40,500);
        mTextArea.setLineWrap(true);
        mTextArea.setFont(mSource.getFont());
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBackground(getBackground());
        scrollPanel.setBorder(BorderFactory.createEmptyBorder()); 
	scrollPanel.setPreferredSize(new Dimension(500, 200));
        //gbc.fill = gbc.VERTICAL;
        gbc.fill = gbc.BOTH;
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
        gb3.setConstraints(scrollPanel, gbc);
        content.add(scrollPanel);

        return content;
    }
}
