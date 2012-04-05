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
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;

import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Display this dialog to get a password.
 *
 * @author chrisho
 * @author jpanchen
 * @version $Revision$, $Date$
 * @date        07/21/98
 */

public class CMSPasswordDialog extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final int WIDTH = 300;
    private static final int HEIGHT = 216;

    private JLabel mUsernameField;      // username textfield
    private JPasswordField  mPasswordField; // password field
    private JPasswordField  mPasswordFieldAgain;    // password field
    private JPasswordField  mOldPasswordField; // old password
    private boolean mCanceled = true;       // exit state of the dialog
    private String  mUsername;              // username
    private String  mPassword;              // password
    private static final String PREFIX = "PASSWDDIALOG";
    private JFrame mParentFrame;
    private ResourceBundle mResource;
    private AdminConnection mAdmin;
    private JButton mOK, mCancel, mHelp;


    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * @param parent parent frame
     */
    public CMSPasswordDialog(JFrame parent, AdminConnection conn, String uid) {
        super(parent, true);
        mParentFrame = parent;
        mAdmin = conn;
        mResource =
          ResourceBundle.getBundle(CMSAdminResources.class.getName());
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
          new JLabel(mResource.getString(PREFIX+"_LABEL_USERID_LABEL"));
        lUsername.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_USERID_TTIP"));

        mUsernameField = new JLabel(uid);


        CMSAdminUtil.addEntryField(contentPanel, lUsername, mUsernameField,
          gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lOldPassword=
          new JLabel(mResource.getString(PREFIX+"_LABEL_OLDPASSWORD_LABEL"));
        lOldPassword.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_OLDPASSWORD_TTIP"));
        mOldPasswordField = new JPasswordField();
        mOldPasswordField.getDocument().addDocumentListener(this);
        mOldPasswordField.addMouseListener(this);
        CMSAdminUtil.addEntryField(contentPanel, lOldPassword,
          mOldPasswordField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lPassword=
          new JLabel(mResource.getString(PREFIX+"_LABEL_PASSWORD_LABEL"));
        lPassword.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_PASSWORD_TTIP"));
        mPasswordField = new JPasswordField();
        mPasswordField.getDocument().addDocumentListener(this);
        mPasswordField.addMouseListener(this);
        CMSAdminUtil.addEntryField(contentPanel, lPassword, mPasswordField,
          gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lPasswordAgain=
          new JLabel(mResource.getString(PREFIX+"_LABEL_PASSWORD_AGAIN_LABEL"));
        lPassword.setToolTipText(
          mResource.getString(PREFIX+"_LABEL_PASSWORD_AGAIN_TTIP"));
        mPasswordFieldAgain = new JPasswordField();
        mPasswordFieldAgain.getDocument().addDocumentListener(this);
        mPasswordFieldAgain.addMouseListener(this);
        CMSAdminUtil.addEntryField(contentPanel, lPasswordAgain,
          mPasswordFieldAgain, gbc);

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
        this.show();

        /* Cancel if the window is closed */
        addWindowListener(
            new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
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
            String userid = mUsernameField.getText().trim();
            String oldpassword = mOldPasswordField.getText().trim();
            String newpassword = mPasswordField.getText().trim();
            String passwordAgain = mPasswordFieldAgain.getText().trim();

            /* PROACTIVE VERIFICATION
            if (oldpassword.equals("") || newpassword.equals("") ||
              passwordAgain.equals("")) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource,
                  PREFIX, "EMPTYFIELD", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            */
           if (!newpassword.equals(passwordAgain)) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource,
                  PREFIX, "CONFIRMED", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }


            NameValuePairs nvps = new NameValuePairs();
            nvps.put(Constants.PR_OLD_AGENT_PWD, oldpassword);
            nvps.put(Constants.PR_AGENT_PWD, newpassword);

            try {
                mAdmin.modify(DestDef.DEST_KRA_ADMIN,
                  ScopeDef.SC_AGENT_PWD, userid, nvps);
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  ex.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                if (!ex.getMessage().equals("Server Error"))
                    return;
            }

            mCanceled = false;
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
        return CMSAdminUtil.makeJButtonPanel(buttons);
    }

    //set buttons
    private void setButtons() {
        if ( (mPasswordField.getText().trim().equals("")) ||
             (mPasswordFieldAgain.getText().trim().equals("")) ||
             (mOldPasswordField.getText().trim().equals("")) ) {
            mOK.setEnabled(false);
        } else {
            mOK.setEnabled(true);
        }
    }

}
