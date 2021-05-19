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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Display this dialog to get the instance name and password.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class AuthDialog extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "AUTHDIALOG";

    private static final int WIDTH = 300;
    private static final int HEIGHT = 150;
    private JPasswordField mPasswordField;
    private boolean mCanceled = true;       // exit state of the dialog
    private String mPassword;
    private ResourceBundle mResource;
    private JButton mOK, mCancel;
    private KeyListener mTextFieldKeyListener;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * @param parent parent frame
     */
    public AuthDialog(JFrame parent) {
        super(parent, true);
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(contentPanel, gbc);
        center.add(contentPanel);

        CMSAdminUtil.resetGBC(gbc);
        JLabel lPassword =
          new JLabel(mResource.getString(PREFIX+"_LABEL_PASSWORD_LABEL"));
        mPasswordField = new JPasswordField();
        mPasswordField.addKeyListener(mTextFieldKeyListener);
        mPasswordField.getDocument().addDocumentListener(this);
        mPasswordField.addMouseListener(this);

        CMSAdminUtil.addEntryField(contentPanel, lPassword, mPasswordField,
          gbc);

        JPanel actionPanel = makeActionPane();

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(actionPanel, gbc);
        center.add(actionPanel);

        getContentPane().add("Center",center);

        mCanceled=false;
        mPassword = "";

        setSize( WIDTH, HEIGHT );

        addWindowListener(
            new WindowAdapter() {
                @Override
                public void windowOpened(WindowEvent e) {
                    mPasswordField.requestFocus();
                }
            }
        );

        addWindowListener(
            new WindowAdapter() {
                @Override
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

    public String getPassword() {
        return mPassword;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/
    @Override
    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mOK)) {
            mPassword = mPasswordField.getText().trim();
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
        if (mPasswordField.getText().trim().equals("")){
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
		@Override
        public void keyTyped(KeyEvent e) {
		}

		@Override
        public void keyPressed(KeyEvent e) {
		}

		@Override
        public void keyReleased(KeyEvent e) {
			if(e.getKeyCode() == KeyEvent.VK_ENTER) {
				if (!mPasswordField.getText().trim().equals("")) {
                        mOK.doClick();
                }
			}
		}
	}

}
