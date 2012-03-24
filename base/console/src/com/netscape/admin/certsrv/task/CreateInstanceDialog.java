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
package com.netscape.admin.certsrv.task;

import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Display this dialog to get the certificate
 * instance name.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CreateInstanceDialog extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CREATEINSTANCE";

    private static final int WIDTH = 300;
    private static final int HEIGHT = 150;
    private JTextField  mInstanceField;     // username textfield
    private boolean mCanceled = true;       // exit state of the dialog
    private String  mInstanceName;              // username
    private JFrame mParentFrame;
    private ResourceBundle mResource;
    private JButton mOK, mCancel;
    private KeyListener mTextFieldKeyListener;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * @param parent parent frame
     */
    public CreateInstanceDialog(JFrame parent) {
        super(parent, true);
        mParentFrame = parent;
        mResource =
          ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mTextFieldKeyListener = new TextFieldKeyListener();
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);

        JPanel center = new JPanel();
        getContentPane().setLayout(new BorderLayout());
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        JPanel contentPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        contentPanel.setLayout(gb1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(contentPanel, gbc);
        center.add(contentPanel);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lUsername =
          new JLabel(mResource.getString(PREFIX+"_LABEL_INSTANCE_LABEL"));
        lUsername.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_INSTANCE_TTIP"));

        mInstanceField = new JTextField();
        mInstanceField.addKeyListener(mTextFieldKeyListener);
        mInstanceField.getDocument().addDocumentListener(this);
        mInstanceField.addMouseListener(this);

        CMSAdminUtil.addEntryField(contentPanel, lUsername, mInstanceField,
          gbc);

        JPanel actionPanel = makeActionPane();

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(actionPanel, gbc);
        center.add(actionPanel);

        getContentPane().add("Center",center);

        mCanceled=false;
        mInstanceName="";

        setSize( WIDTH, HEIGHT );

        addWindowListener(
            new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    //setVisible(false);
                    dispose();
                    mCanceled = true;
                }
            }
        );

    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     *  return the exit status of the dialog
     *
     * @return true if the user hits the cancel button.
     */
    public boolean isCancel() {
        return mCanceled;
    }

    /**
     *  Returns the username typed in by the user, on OK.
     *
     * @return The selected username, if the user hits the OK button.
     */
    public String getInstanceName() {
        return mInstanceName;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/
    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mOK)) {
            mInstanceName = mInstanceField.getText().trim();

            mCanceled = false;
            //setVisible(false);
            this.dispose();
            return;

        }
        if (evt.getSource().equals(mCancel)) {
            //setVisible(false);
            mCanceled = true;
            this.dispose();
            return;
        }
    }

    //== DocumentListener ==
    public void insertUpdate(DocumentEvent e) {
        setButtons();
    }

    public void removeUpdate(DocumentEvent e){
        setButtons();
    }

    public void changedUpdate(DocumentEvent e){
        setButtons();
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {
        setButtons();
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null,
          this);
        mOK.setEnabled(false);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL",
          null, this);

        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel(buttons, false);
    }

    //set buttons
    private void setButtons() {
        if (mInstanceField.getText().trim().equals("")){
            mOK.setEnabled(false);
        } else {
            mOK.setEnabled(true);
            getRootPane().setDefaultButton(mOK);
        }
    }

    /**
     * Inner class which handles key events for JTextField components.
     */
	class TextFieldKeyListener implements KeyListener
	{
		public void keyTyped(KeyEvent e) {
		}

		public void keyPressed(KeyEvent e) {
		}

		public void keyReleased(KeyEvent e) {
			if(e.getKeyCode() == KeyEvent.VK_ENTER) {
				if (!mInstanceField.getText().trim().equals("")) {
                        mOK.doClick();
                }
			}
		}
	}

}