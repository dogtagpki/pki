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
package com.netscape.admin.certsrv.ug;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
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
 * Certificate Import Editor
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class CertViewDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String  PREFIX = "CERTVIEWDIALOG";

    private ResourceBundle mResource;
    private JTextArea mTextArea;
    private JLabel mCertNameField;

    private JButton mOK;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CertViewDialog(JFrame parent) {
        super(parent,true);
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        //setSize(800, 700);
        setSize(400, 350);
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
    public void showDialog(String name, String pp) {
        //initialize and setup
        String certName = "";
        if (name != null && name.length() > 0) {
            int j = name.indexOf("Subject:");
            int i = name.indexOf("Issuer:");
            if (j < i) {
                certName = name.substring(j, i);
            }
        }
        mCertNameField.setText(certName);
        mTextArea.setText(pp);
        this.setVisible(true);
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	public void actionPerformed(ActionEvent evt) {
	    if (evt.getSource().equals(mOK)) {
	        this.setVisible(false);
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
        gbc.fill = GridBagConstraints.BOTH;
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
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
        //JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "CERTNAME", null);
        mCertNameField = new JLabel();
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.weightx=1.0;
        gbc.weightx=0.0;
        gb3.setConstraints(mCertNameField, gbc);
        content.add(mCertNameField);
        //CMSAdminUtil.addEntryField(content, label1, mCertNameField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "PP", null);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.weightx=1.0;
        gb3.setConstraints(label2, gbc);
        content.add(label2);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",40,70);
        Font f = new Font("Monospaced", Font.PLAIN, 12);
        if (f != null) mTextArea.setFont(f);
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBorder(BorderFactory.createLoweredBevelBorder());
	scrollPanel.setPreferredSize(new Dimension(300, 500));
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
//	gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
//         CMSAdminUtil.COMPONENT_SPACE,
//         CMSAdminUtil.COMPONENT_SPACE);
        gb3.setConstraints(scrollPanel, gbc);
        content.add(scrollPanel);

        return content;
    }
}
