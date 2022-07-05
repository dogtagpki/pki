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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.management.client.util.Debug;


/**
 * Policy Implementation Registration Editor
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated
public class ProfileRegisterDialog extends JDialog
    implements ActionListener, DocumentListener, MouseListener
{

    private final static String PREFIX = "PROFILEREGISTERDIALOG";


    /*==========================================================
     * variables
     *==========================================================*/
    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;

    private JTextField mNameField, mClassField, mTypeField, mDescField;
    private JButton mOK, mCancel;

    protected String mDestination;    //DEST_TAG to support RA/KRA/CA dest
    protected String mScope;
    protected String mPrefix;
    private boolean mIsOK = false;
    protected boolean mType = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileRegisterDialog(String prefix, JFrame parent, AdminConnection conn) {
        super(parent,true);
        mParentFrame = parent;
        mPrefix = prefix;
        mConnection = conn;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(360, 216);
        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        //setDisplay(); SUBCLASS MUST call setDiaply() in its constructor
    }

    public ProfileRegisterDialog(JFrame parent, AdminConnection conn) {
        this(PREFIX, parent, conn);
        mType = true;
        setDisplay();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * show the windows
     */
    public void showDialog(String destination, String scope) {
        //initialize and setup
        mNameField.setText("");
        mClassField.setText("");
        mTypeField.setText("");
        mDescField.setText("");
        mDestination=destination;
        mScope=scope;
        this.setVisible(true);
    }

    protected void setDestination(String destination) {
        mDestination = destination;
    }

    protected void setScope(String scope) {
        mScope = scope;
    }

    public boolean isOK() {
        return mIsOK;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	@Override
    public void actionPerformed(ActionEvent evt) {

	    if (evt.getSource().equals(mCancel)) {
            mIsOK = false;
            this.setVisible(false);
        }

        if (evt.getSource().equals(mOK)) {

            /* REPLACED BY PROACTIVE ENFORCEMENT
            if (mNameField.getText().trim().equals("")) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource, mPrefix,
                    "NONAME", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            if (mClassField.getText().trim().equals("")) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource, mPrefix,
                    "NOCLASS", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            */

            //save value
            try {
                addImpl();
            } catch (EAdminException e) {
                //display error dialog
                Debug.println(e.toString());
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                mIsOK = false;
                return;
            }
            mIsOK = true;
            this.setVisible(false);
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
	 * protected methods
     *==========================================================*/

    protected void setDisplay() {
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

    /*==========================================================
	 * private methods
     *==========================================================*/

    //set arrow buttons
    private void setButtons() {
        if ( (mNameField.getText().trim().equals("")) ||
             (mClassField.getText().trim().equals("")) ) {
            mOK.setEnabled(false);
        } else {
            mOK.setEnabled(true);
        }
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, mPrefix, "OK", null, this);
        mOK.setEnabled(false);
        mCancel = CMSAdminUtil.makeJButton(mResource, mPrefix, "CANCEL", null, this);
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
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "NAME", null);
        mNameField = new JTextField();
        mNameField.getDocument().addDocumentListener(this);
        mNameField.addMouseListener(this);
        CMSAdminUtil.addEntryField(content, label1, mNameField, gbc);

        CMSAdminUtil.resetGBC(gbc);
       // gbc.gridheight = gbc.REMAINDER;
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "CLASS", null);
        mClassField = new JTextField();
        mClassField.getDocument().addDocumentListener(this);
        mClassField.addMouseListener(this);
        CMSAdminUtil.addEntryField(content, label2, mClassField, gbc);

          CMSAdminUtil.resetGBC(gbc);
      //    gbc.gridheight = gbc.REMAINDER;
          JLabel label3 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "TYPE", null);
          mTypeField = new JTextField();
          mTypeField.getDocument().addDocumentListener(this);
          mTypeField.addMouseListener(this);
          CMSAdminUtil.addEntryField(content, label3, mTypeField, gbc);

          CMSAdminUtil.resetGBC(gbc);
          gbc.gridheight = GridBagConstraints.REMAINDER;
          JLabel label4 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "DESC", null);
          mDescField = new JTextField();
          mDescField.getDocument().addDocumentListener(this);
          mDescField.addMouseListener(this);
          CMSAdminUtil.addEntryField(content, label4, mDescField, gbc);

        return content;
    }

    //=================================================
    // CONNECT TO SERVER SIDE
    //=================================================

    //add new group information
    private void addImpl() throws EAdminException {

            //construct NVP
            NameValuePairs config = new NameValuePairs();
            config.put(Constants.PR_POLICY_CLASS, mClassField.getText());
            config.put(Constants.PR_POLICY_DESC, mDescField.getText());

            if (mType) {
              mScope=mTypeField.getText();
            }

            //send request
            mConnection.add(mDestination,
                            mScope,
                            mNameField.getText().trim(),
                            config);
    }


}
