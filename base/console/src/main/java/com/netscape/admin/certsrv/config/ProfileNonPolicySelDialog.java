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
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Plugin Selection Dialog
 *
 * @author Jack Pan-chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileNonPolicySelDialog extends JDialog
    implements ActionListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    protected JFrame mParentFrame;
    protected AdminConnection mConnection;
    protected ResourceBundle mResource;
    protected DefaultListModel<JLabel> mListModel;
    protected Hashtable<String, String> mListData;
    protected String mDestination;              //dest flag

    private JScrollPane mScrollPane;
    protected JList<JLabel> mList;

    protected JLabel mLabel;
    protected JButton mOK, mCancel, mHelp;
    protected String mPrefix;
    protected String mScope;
    protected String mInstanceScope;
    protected String mProfileId;
    protected String mHelpToken;
    protected String mExtraDestination;
	protected CMSPluginInstanceTab mPluginInstanceDialog;
	protected CMSBaseResourceModel mModel=null;


    public ProfileNonPolicySelDialog (
            String profileId,
            String prefix,
            JFrame parent,
            AdminConnection conn,
            String dest, String scope)
    {
        this(profileId, prefix, parent, conn, dest, null, scope, null);
    }

    public ProfileNonPolicySelDialog (
			String profileId,
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest, String extraDest, String scope)
	{
		this(	profileId, prefix,
				parent,
				conn,
				dest, extraDest, scope,
				null );
	}

    public ProfileNonPolicySelDialog(
            String profileId,
            String prefix,
            JFrame parent,
            AdminConnection conn,
            String dest, String scope,
            CMSPluginInstanceTab pluginType)
    {
        this(profileId, prefix, parent, conn, dest, null, scope, pluginType);
    }

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileNonPolicySelDialog(
			String profileId,
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest, String extraDest, String scope,
			CMSPluginInstanceTab pluginType)
	{
        super(parent,true);
        mProfileId = profileId;
        mParentFrame = parent;
        mConnection = conn;
        mDestination = dest;
        mExtraDestination = extraDest;
        mScope = scope;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mListModel = new DefaultListModel<>();
        mListData = new Hashtable<>();
        mPrefix = prefix;
		mPluginInstanceDialog = pluginType;

        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setSize(400, 230);
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
    }

    /*==========================================================
     * public methods
     *==========================================================*/

	public void setModel(CMSBaseResourceModel model)
	{
		mModel = model;
	}

    /**
     * show the windows
     * @param users list of current groups
     */
    public void showDialog() {

        mListModel.clear();

        if(!update())
            return;
        this.setVisible(true);
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent evt) {

		if (evt.getSource().equals(mOK)) {

			// check selection lists
			if (mList.getSelectedIndex() < 0) {
            			CMSAdminUtil.showErrorDialog(mParentFrame, mResource, "Must select default", CMSAdminUtil.ERROR_MESSAGE);
			}

            NameValuePairs response = null;

            String scope = "";
            if (mPrefix.equals("PROFILEINPUTSELDIALOG")) {
                scope = ScopeDef.SC_PROFILE_INPUT;
            } else if (mPrefix.equals("PROFILEOUTPUTSELDIALOG")) {
                scope = ScopeDef.SC_PROFILE_OUTPUT;
            }

            ProfileNonPolicyNewDialog dialog =
				new ProfileNonPolicyNewDialog(
					response,
                	mParentFrame,
                	mConnection,
                	mExtraDestination, scope, true);

			dialog.setModel(mModel);

            String name = mListModel.elementAt(mList.getSelectedIndex()).getText();

            dialog.showDialog(response, mProfileId, getID(name));

            if(!dialog.isOK()) {
                this.dispose();
                return;
            }

            //response = dialog.getData();
           // String name = dialog.getRuleName();

          //  Debug.println(response.toString());

			dialog.dispose();
            this.dispose();
        }

        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setArrowButtons();
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {
        setArrowButtons();
    }
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {
        setArrowButtons();
    }

    protected void setDisplay() {
		Debug.println("*** PluginSelectionDialog.setDisplay() - 1");
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

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

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, mPrefix, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, mPrefix, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, mPrefix, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeContentPane() {
		Debug.println("*** PluginSelectionDialog.makeContentPane() - 0");
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
		Debug.println("*** PluginSelectionDialog.makeContentPane() - 1");
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        JLabel label = CMSAdminUtil.makeJLabel(mResource, mPrefix,
           "SELECT", null);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gb.setConstraints(label, gbc);
        mListPanel.add(label);

		Debug.println("*** PluginSelectionDialog.makeContentPane() - 2");
        mList = CMSAdminUtil.makeJList(mListModel,9);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;
    }

    //set arrow buttons
    private void setArrowButtons() {

        if (mList.getSelectedIndex()< 0) {
            mOK.setEnabled(false);
            return;
        }

        mOK.setEnabled(true);
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //save order information to the server
    protected boolean update() {

        NameValuePairs response;
        NameValuePairs params = new NameValuePairs();
        try {
            response = mConnection.search(mDestination, mScope,
                               params);
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        Debug.println(response.toString());

        //parse the data
        String[] vals = new String[response.size()];
        int i=0;
        for (String name : response.keySet()) {
            name = name.trim();
            String val = response.get(name);
            StringTokenizer st = new StringTokenizer(val, ",");
            String className = st.nextToken();
            String desc = st.nextToken();
            String friendlyName = st.nextToken();
            vals[i++] = friendlyName.trim();
            mListData.put(name, friendlyName);
        //    vals[i++] = ((String)e.nextElement()).trim();
			Debug.println("PluginSelectionDialog::update() - adding '"+vals[i-1]+"'");
        }

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
			try {
                mListModel.addElement(new JLabel(vals[y], JLabel.LEFT));
			} catch (Exception ex) {
			}
        }

        return true;
    }

    private String getID(String name) {
        Enumeration<String> keys = mListData.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String val = mListData.get(key);
            if (val.equals(name)) {
                return key;
            }
        }
        return "";
    }
}
