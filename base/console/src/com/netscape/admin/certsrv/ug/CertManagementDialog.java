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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * User Certificate Management Dialog - <p>
 *
 * The administrator can use this dialog to management the
 * certificates of specific user. This allows the import of
 * new certificates and delete/view of existing certificates.
 * 
 * This dialog is launched by clicking on the certificate button
 * on the main user management tab.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug.CertImportDialog
 * @see com.netscape.admin.certsrv.ug.CertViewDialog
 * @see com.netscape.admin.certsrv.ug.UserTab
 */
public class CertManagementDialog extends JDialog
    implements ActionListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "CERTMANAGEMENTDIALOG";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;
    protected DefaultListModel mDataModel;
    protected Vector mPPData;
    protected String mUID;              //dest flag
    protected CertViewDialog mViewDialog = null;      //keeping a copy for reuse
    protected CertImportDialog mCertDialog = null;    //keeping a copy for reuse

    private JScrollPane mScrollPane;
    private JList mList;

    private JButton mOK, mCancel, mAdd, mDelete, mView, mHelp;
    private final static String HELPINDEX = 
      "usersgroups-certsrv-manage-usercert-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CertManagementDialog(JFrame parent, AdminConnection conn) {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new DefaultListModel();
        mPPData = new Vector();
        setSize(800, 216);
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
     * @param uid current user id
     */
    public void showDialog(String uid) {
        mUID = uid;
        
        if (!refresh())
            return;
        setButtons();
        this.show();
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {
            //nothing to do here
            this.dispose();
        } else if (evt.getSource().equals(mCancel)) {
            this.dispose();
        } else if (evt.getSource().equals(mAdd)) {
            //call cert import editor
            if (mCertDialog==null)
                mCertDialog = new CertImportDialog(mParentFrame);
            mCertDialog.showDialog();
            if (!mCertDialog.isOK())
                return;
            addCert(mCertDialog.getB64E());
            refresh();
            setButtons();
        } else if (evt.getSource().equals(mDelete)) {
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame, mResource, "USERCERTS",
              "DELETE", JOptionPane.INFORMATION_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
                deleteCert();
                refresh();
                setButtons();
            }
        } else if (evt.getSource().equals(mView)) {
            if (mViewDialog==null)
                mViewDialog = new CertViewDialog(mParentFrame);
            String id = ((JLabel)mDataModel.elementAt(mList.getSelectedIndex())).getText();
            mViewDialog.showDialog(id,(String)mPPData.elementAt(mList.getSelectedIndex()));
        } else if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {}

    /*==========================================================
	 * private methods
     *==========================================================*/
    
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
        gbc.fill = gbc.BOTH;
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

    /**
     * create the bottom action button panel
     */
    protected JPanel createUDButtonPanel() {
        //up, down buttons required
        //actionlister to this object
        mAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "IMPORT", null, this);
        mDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", null, this);
        mView = CMSAdminUtil.makeJButton(mResource, PREFIX, "VIEW", null, this);
		JButton[] buttons = { mAdd, mDelete, mView};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
	// JButton[] buttons = { mOK, mHelp};
	JButton[] buttons = { mOK};
		JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mList = CMSAdminUtil.makeJList(mDataModel,10);
		mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
		mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
		mList.addMouseListener(this);
		mScrollPane.setBackground(Color.white);
		mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,CMSAdminUtil.COMPONENT_SPACE,0,0);
        gb.setConstraints(mScrollPane, gbc);
		mListPanel.add(mScrollPane);

	    JPanel buttonPanel = createUDButtonPanel();
		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                0,0,CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(buttonPanel, gbc);
		mListPanel.add(buttonPanel);

        return mListPanel;
    }

    /**
     * set buttons - proactive verification
     */
    private void setButtons() {

        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mList.getSelectedIndex());
        if (mList.getSelectedIndex()< 0) {
            mDelete.setEnabled(false);
            mView.setEnabled(false);
            return;
        }
        mDelete.setEnabled(true);
        mView.setEnabled(true);
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //refresh the table content
    private boolean refresh() {
        
        mDataModel.clear();
        mPPData.removeAllElements();
        
        NameValuePairs response;
        try {
            response = mConnection.read(DestDef.DEST_USER_ADMIN,
                                   ScopeDef.SC_USER_CERTS,
                                   mUID, new NameValuePairs());
        } catch (EAdminException e) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;   
        }
        
        //parse data
        String[] vals = new String[response.size()];
        int i=0;
        
        for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
            vals[i++] = ((String)e.nextElement()).trim();
        }
        
        CMSAdminUtil.bubbleSort(vals);
        
        for (int y=0; y< vals.length ; y++) {
            String str = reformat(vals[y]);
            mDataModel.addElement(new JLabel(str,
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_SMALL),
                JLabel.LEFT));
            mPPData.addElement(response.getValue(vals[y]));
        }
        
        return true;
    }

    /**
     * Change DN from the following format:
     *   Serial:0x0     Subject:<DN>   Issuer:<DN>
     * to the following fomrat:
     *   <version>;<serial>;<subject>;<issuer>
     */
    private String toServerFormat(String val) {
      if (val == null)
        return "";
      int subject_pos = val.indexOf("Subject:");
      if (subject_pos == -1)
        return "";
      int issuer_pos = val.indexOf("Issuer:");
      if (issuer_pos == -1)
        return "";
      // we lost the version in reformat()

      String serial = val.substring(9, subject_pos).trim();
      long num = CMSAdminUtil.hexToLong(serial);
      try {
          return "-1;" + 
	     num + ";" +
             val.substring(issuer_pos+7).trim() + ";" +
             val.substring(subject_pos+8, issuer_pos).trim();
      } catch (NumberFormatException e) {
          return "-1;" + num+";"+
               val.substring(issuer_pos+7).trim() + ";" +
               val.substring(subject_pos+8, issuer_pos).trim();
      }
    }

    // swap the issuer name order with the subject name
    private String reformat(String val) {

		String name = "";

		StringTokenizer st = new StringTokenizer(val,";",false);
		String version=null;  // I think this is cert version #
		String serial=null;
		String issuer=null;
		String subject=null;

		try { 
			version = st.nextToken();
			serial  = st.nextToken();
			issuer  = st.nextToken();
			subject = st.nextToken();
		} catch (Exception e) {}
			
		try {
			if (serial != null) {
				String hexserial = Integer.toHexString(Integer.parseInt(serial));
				name = name + "Serial:0x"+hexserial;
			}
		} catch (Exception e) {}
		

		if (subject != null) {
			name = name + "     Subject:"+subject;
		}

		if (issuer != null) {
			name = name + "     Issuer:"+issuer;
		}

        return name;
    }
    
    private void addCert(String B64E) {
        //send comment to server for the removal of user
        NameValuePairs config = new NameValuePairs();
        config.add(Constants.PR_USER_CERT, cleanupCertData(B64E));
        try {
            mConnection.add(DestDef.DEST_USER_ADMIN,
                            ScopeDef.SC_USER_CERTS,
                            mUID,
                            config);
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
    }    
    
    /**
     * routine to cleanup the certificate data
     * this removes end of line embedded in the
     * certificate data.
     *
     * @param data b64e cert request blob
     */
    private String cleanupCertData(String data) {
        StringBuffer input = new StringBuffer(data);
        StringBuffer buff = new StringBuffer();
        for (int i=0; i< input.length(); i++) {
            char c = input.charAt(i);
            if ((c != '\n') && (c != '\r'))
                buff.append(c);
        }
        return buff.toString();
    }    
    
    private void deleteCert() {
        //get entry name
        String dn = ((JLabel)mDataModel.elementAt(mList.getSelectedIndex())).getText();
        dn = toServerFormat(dn);
        NameValuePairs config = new NameValuePairs();
        config.add(Constants.PR_USER_CERT,dn);
        
        //send comment to server for the removal of user
        try {
            mConnection.modify(DestDef.DEST_USER_ADMIN,
                               ScopeDef.SC_USER_CERTS,
                               mUID,
                               config);
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
    }

}
