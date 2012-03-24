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
package com.netscape.admin.certsrv;

import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Display this dialog to get a password.
 *
 * @author chrisho
 * @version $Revision$, $Date$
 * @date        07/21/98
 */

public class CMSPassword extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final int WIDTH = 300;
    private static final int HEIGHT = 150;
    private static final String HELPINDEX =
      "authentication-certsrv-auth-dialog-help";

    private JTextField  mUsernameField;     // username textfield
    private JPasswordField  mPasswordField; // password field
    private boolean mCanceled = true;       // exit state of the dialog
    private String  mUsername;              // username
    private String  mPassword;              // password
    private static final String PREFIX = "CMSPASSWORD";
    private JFrame mParentFrame;
    private ResourceBundle mResource;
    private JButton mOK, mCancel, mHelp;
    private KeyListener mTextFieldKeyListener;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * @param parent parent frame
     */
    public CMSPassword(JFrame parent) {
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
          new JLabel(mResource.getString(PREFIX+"_LABEL_UID_LABEL"));
        lUsername.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_UID_TTIP"));

        mUsernameField = new JTextField();
        mUsernameField.addKeyListener(mTextFieldKeyListener);
        mUsernameField.getDocument().addDocumentListener(this);
        mUsernameField.addMouseListener(this);

        CMSAdminUtil.addEntryField(contentPanel, lUsername, mUsernameField,
          gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lPassword=
          new JLabel(mResource.getString(PREFIX+"_LABEL_PWD_LABEL"));
        lPassword.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_PWD_TTIP"));
        mPasswordField = new JPasswordField();
        mPasswordField.addKeyListener(mTextFieldKeyListener);
        mPasswordField.getDocument().addDocumentListener(this);
        mPasswordField.addMouseListener(this);
        CMSAdminUtil.addEntryField(contentPanel, lPassword, mPasswordField,
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
        mUsername="";
        mPassword="";

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

        addWindowListener(
            new WindowAdapter() {
                public void windowOpened(WindowEvent e) {
                    mUsernameField.requestFocus();
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
    public String getUsername() {
        return mUsername;
    }

    /**
     *  Return the password typed in by the user, on OK.
     *
     * @return The selected password, if the user hits the OK button.
     */
    public String getPassword() {
        return mPassword;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/
    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mOK)) {
            mUsername = mUsernameField.getText().trim();
            mPassword = mPasswordField.getText().trim();

            /* USE PROACTIVE VERIFICATION
            if (userid.equals("") || newpassword.equals("")) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource,
                  PREFIX, "EMPTYFIELD", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            */

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
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
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
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP",
          null, this);
        
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel(buttons, true);
    }

    //set buttons
    private void setButtons() {
        if ( (mUsernameField.getText().trim().equals("")) ||
             (mPasswordField.getText().trim().equals("")) ) {
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
				if ( (!mUsernameField.getText().trim().equals("")) &&
                     (!mPasswordField.getText().trim().equals("")) ) {
                        mOK.doClick();
                }
			}
		}
	}

}
