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
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;

/**
 * Certificate Import Editor - this UI will take Base64Encoded
 * certificate block with BEGIN and END comment and deliver it
 * to server side for processing. EOL, CRT, EOF characters are
 * removed from the output.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug.CertManagementDialog
 */
public class CertImportDialog extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String  PREFIX = "CERTIMPORTDIALOG";

    private ResourceBundle mResource;

    private JTextArea mTextArea;
    private JButton mOK, mCancel;
    private String mB64E;
    private boolean mIsOk = false;
    private JButton mPaste;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CertImportDialog(JFrame parent) {
        super(parent,true);
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(500, 400);
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
    public void showDialog() {
        //initialize and setup
        mTextArea.setText("");
        mIsOk = false;
        this.setVisible(true);
    }

    /**
     * get Base 64 Encoded blob
     */
    public String getB64E() {
        return mB64E;
    }

    /**
     * get the exit code
     * @return true if ok; otherwise false
     */
    public boolean isOK() {
        return mIsOk;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	@Override
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mPaste)) {
           mTextArea.paste();
           return;
        }

	    if (evt.getSource().equals(mCancel)) {
            this.setVisible(false);
        }

        if (evt.getSource().equals(mOK)) {

            //set values
            mB64E = mTextArea.getText().trim();
            mIsOk = true;
            this.setVisible(false);
        }
	}

    //==== MOUSELISTENER ======================
    @Override
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    @Override
    public void mousePressed(MouseEvent e) {}
    @Override
    public void mouseReleased(MouseEvent e) {}
    @Override
    public void mouseEntered(MouseEvent e) {}
    @Override
    public void mouseExited(MouseEvent e) {
        setButtons();
    }

    //== DocumentListener ==
    @Override
    public void insertUpdate(DocumentEvent e) {
        setButtons();
    }

    @Override
    public void removeUpdate(DocumentEvent e){
        setButtons();
    }

    @Override
    public void changedUpdate(DocumentEvent e){
        setButtons();
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

    /**
     * set buttons - proactive verification
     */
    private void setButtons() {
        if (mTextArea.getText().trim().equals("")) {
            mOK.setEnabled(false);
        } else {
            mOK.setEnabled(true);
        }
    }

    /**
     * Setup the initial UI components
     */
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
        mOK.setEnabled(false);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
		JButton[] buttons = { mOK, mCancel};
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "B64E", null);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.weightx=0.0;
        gb3.setConstraints(label2, gbc);
        content.add(label2);

        CMSAdminUtil.resetGBC(gbc);
        mPaste = CMSAdminUtil.makeJButton(mResource, PREFIX, "PASTE", null, this);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.weightx=1.0;
        gb3.setConstraints(mPaste, gbc);
        content.add(mPaste);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",40,70);
        Font f = new Font("Monospaced", Font.PLAIN, 12);
        if (f != null) mTextArea.setFont(f);
        mTextArea.getDocument().addDocumentListener(this);
        mTextArea.addMouseListener(this);
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
        gb3.setConstraints(scrollPanel, gbc);
        content.add(scrollPanel);

        return content;
    }
}
