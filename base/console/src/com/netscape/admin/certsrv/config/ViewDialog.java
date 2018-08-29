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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;

/**
 * Policy Implementation Information viewer
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ViewDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String  PREFIX = "VIEWDIALOG";

    private ResourceBundle mResource;
    private JTextArea mTextArea;
    private JLabel mNameField, mClassField;

    private JButton mOK;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ViewDialog(JFrame parent) {
        super(parent,true);
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(400, 200);
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
    public void showDialog(String name, String classname, String desc) {
        //initialize and setup
        mNameField.setText(name);
        mClassField.setText(classname);
        mTextArea.setText(CMSAdminUtil.wrapText(desc,50));
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
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content, gbc);
		center.add(content);

		//action panel
		JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = GridBagConstraints.REMAINDER;
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
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "NAME", null);
        mNameField = new JLabel();
        CMSAdminUtil.addEntryField(content, label1, mNameField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "CLASS", null);
        mClassField = new JLabel();
        CMSAdminUtil.addEntryField(content, label2, mClassField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "DESC", null);
        label3.setHorizontalAlignment(JLabel.RIGHT);
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,0,0);
        gb3.setConstraints(label3, gbc);
        content.add(label3);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",30,10);
        mTextArea.setFont(mClassField.getFont());
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBackground(getBackground());
        scrollPanel.setBorder(BorderFactory.createEmptyBorder());
	scrollPanel.setPreferredSize(new Dimension(300, 500));
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
        gb3.setConstraints(scrollPanel, gbc);
        content.add(scrollPanel);

        return content;
    }
}
