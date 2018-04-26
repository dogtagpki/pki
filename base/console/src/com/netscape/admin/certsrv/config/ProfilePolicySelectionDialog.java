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
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

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
public class ProfilePolicySelectionDialog extends JDialog
    implements ActionListener, MouseListener, ListSelectionListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    protected JFrame mParentFrame;
    protected AdminConnection mConnection;
    protected ResourceBundle mResource;
    protected DefaultListModel<JLabel> mConstraintModel;
    protected DefaultListModel<JLabel> mDefaultModel;
    protected String mDestination;              //dest flag

    private JScrollPane mScrollPane;
    protected JList<JLabel> mDefaultList, mConstraintList;
    protected Hashtable<String, String> mDefaultData, mConstraintData;
    protected JLabel mDefaultLabel, mConstraintLabel;
    protected JButton mOK, mCancel, mHelp;
    protected String mDefSetId;
    protected String mPrefix;
    protected String mScope;
    protected String mInstanceScope;
    protected String mImageName;
    protected String mProfileId;
    protected String mHelpToken="configuration-certificateprofiles";
	protected CMSPluginInstanceTab mPluginInstanceDialog;
	protected CMSBaseResourceModel mModel=null;
    protected String mExtraDestination;

    public ProfilePolicySelectionDialog(
                        String defSetId,
                        String profileId,
                        String prefix,
                        JFrame parent,
                        AdminConnection conn,
                        String dest)
    {
        this(defSetId, profileId, prefix, parent, conn, dest, null, null);
    }

    public ProfilePolicySelectionDialog(
                        String defSetId,
			String profileId,
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest, String extraDest)
	{
		this(defSetId,	profileId, prefix,
				parent,
				conn,
				dest, extraDest,
				null );
	}

    public ProfilePolicySelectionDialog(
                        String defSetId,
                        String profileId,
                        String prefix,
                        JFrame parent,
                        AdminConnection conn,
                        String dest,
                        CMSPluginInstanceTab pluginType) {
        this(defSetId, profileId, prefix, parent, conn, dest, null, pluginType);
    }

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfilePolicySelectionDialog(
			String defSetId,
			String profileId,
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest, String extraDest,
			CMSPluginInstanceTab pluginType)
	{
        super(parent,true);
	mDefSetId = defSetId;
	mProfileId = profileId;
        mParentFrame = parent;
        mConnection = conn;
        mDestination = dest;
        mExtraDestination = extraDest;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDefaultModel = new DefaultListModel<>();
        mConstraintModel = new DefaultListModel<>();
        mDefaultData = new Hashtable<>();
        mConstraintData = new Hashtable<>();
        mPrefix = prefix;
		mPluginInstanceDialog = pluginType;

        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setSize(440, 250);
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

        mConstraintModel.clear();
        mDefaultModel.clear();

        if(!update("defaultPolicy", mDefaultModel, mDefaultData))
            return;
/*
        if(!update("constraintPolicy", mConstraintModel))
            return;
*/
/*
        refresh();
        setArrowButtons();
*/
        this.show();
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent evt) {

		if (evt.getSource().equals(mOK)) {

			// check selection lists
			if (mDefaultList.getSelectedIndex() < 0) {
            			CMSAdminUtil.showErrorDialog(mParentFrame, mResource, "Must select default", CMSAdminUtil.ERROR_MESSAGE);
                return;
			}

			if (mConstraintList.getSelectedIndex() < 0) {
            			CMSAdminUtil.showErrorDialog(mParentFrame, mResource, "Must select constraint", CMSAdminUtil.ERROR_MESSAGE);
                return;
			}

            NameValuePairs response = null;
/*
            try {
                response = getDefaultConfig();
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            Debug.println(response.toString());
            String id = ((JLabel)mDefaultModel.elementAt(mDefaultList.getSelectedIndex())).getText();
            response.add(Constants.PR_POLICY_IMPL_NAME,id);
*/
			ProfilePolicyNewDialog dialog =
				new ProfilePolicyNewDialog(
                                        mDefSetId,
					response,
                	mParentFrame,
                	mConnection,
                	mExtraDestination);

			dialog.setModel(mModel);
			dialog.setInstanceScope(mInstanceScope);

		// profile;defClass;conClass
            String defaultName = mDefaultModel.elementAt(mDefaultList.getSelectedIndex()).getText();
            String conName = mConstraintModel.elementAt(mConstraintList.getSelectedIndex()).getText();


		String namex = mProfileId + ";" + getID(defaultName, mDefaultData) +
            ";" + getID(conName, mConstraintData);
            dialog.showDialog(response,namex);

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

        // default content panel
        mDefaultLabel = CMSAdminUtil.makeJLabel(mResource, mPrefix,
           "DEFAULTNAME", null);
        center.add(mDefaultLabel);

        JPanel content = makeDefaultContentPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content, gbc);
        center.add(content);

	// constraint content panel
        mConstraintLabel = CMSAdminUtil.makeJLabel(mResource, mPrefix,
           "CONSTRAINTNAME", null);
        center.add(mConstraintLabel);

        JPanel content1 = makeConstraintContentPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content1, gbc);
        center.add(content1);

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

    private JPanel makeDefaultContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mDefaultList = CMSAdminUtil.makeJList(mDefaultModel,9);
        mDefaultList.addListSelectionListener(this);
		Debug.println("PluginSelectionDialog.makeContentPane() - making mList("+mDefaultList+")");
        mScrollPane = new JScrollPane(mDefaultList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mDefaultList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mDefaultList.addMouseListener(this);
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

    private JPanel makeConstraintContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mConstraintList = CMSAdminUtil.makeJList(mConstraintModel,9);
		Debug.println("PluginSelectionDialog.makeContentPane() - making mList("+mConstraintList+")");
        mScrollPane = new JScrollPane(mConstraintList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mConstraintList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mConstraintList.addMouseListener(this);
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

        //enable and diable buttons accordingly
        //Debug.println("setArrowButtons() - "+mList.getSelectedIndex());

        if (mDefaultList.getSelectedIndex()< 0 && mConstraintList.getSelectedIndex()<0) {
            mOK.setEnabled(false);
            return;
        }

        mOK.setEnabled(true);
    }

    //refresh the table content
    private void refresh() {
        //mScrollPane.invalidate();
        //mScrollPane.validate();
        //repaint();
    }

    public void valueChanged(ListSelectionEvent e) {
        if (e.getSource().equals(mDefaultList)) {
            if (mDefaultList.getSelectedIndex() < 0)
                return;
            String name = mDefaultModel.elementAt(mDefaultList.getSelectedIndex()).getText();
            NameValuePairs response=null;

            try {
                response = mConnection.read(mDestination,
                  ScopeDef.SC_SUPPORTED_CONSTRAINTPOLICIES,
                  getID(name, mDefaultData), new NameValuePairs());
                Debug.println(response.toString());
            } catch (Exception ex) {
                Debug.println(ex.toString());
            }

            mConstraintModel.clear();
            mConstraintData.clear();
            parseData(response, mConstraintModel, mConstraintData);
            mConstraintList.invalidate();
            mConstraintList.validate();
            repaint();
        }
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //save order information to the server
    protected boolean update(String scope, DefaultListModel<JLabel> model,
      Hashtable<String, String> data) {

        NameValuePairs response;
        NameValuePairs params = new NameValuePairs();
        try {
            response = mConnection.search(mDestination, scope,
                               params);
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        Debug.println(response.toString());

        model.clear();
        data.clear();
        parseData(response, model, data);
        return true;
    }

    private void parseData(NameValuePairs response, DefaultListModel<JLabel> model,
      Hashtable<String, String> data) {
        //parse the data
        String[] vals = new String[response.size()];
        int i=0;
        for (String name : response.keySet()) {
            name = name.trim();
            String val = response.get(name);
            StringTokenizer st = new StringTokenizer(val, ",");
            st.nextToken(); // className
            st.nextToken(); // desc
            String friendlyName = st.nextToken();
            vals[i++] = friendlyName.trim();
            data.put(name, friendlyName);
			Debug.println("PluginSelectionDialog::update() - adding '"+vals[i-1]+"'");
        }

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
			try {
            model.addElement(new JLabel(vals[y],
              CMSAdminUtil.getImage(mImageName), JLabel.LEFT));
			}
			catch (Exception ex) {
				Debug.println("PluginSelectionDialog could not get image for '"+
					mImageName+"'. Adding without image");
            model.addElement(new JLabel(vals[y],
              JLabel.LEFT));
			}
        }
    }

    //this returns the default configuration
    protected NameValuePairs getDefaultConfig() throws EAdminException {
        String name = mDefaultModel.elementAt(mDefaultList.getSelectedIndex()).getText();
        NameValuePairs response;
        response = mConnection.read(mDestination,
          ScopeDef.SC_SUPPORTED_CONSTRAINTPOLICIES, getID(name.trim(), mDefaultData),
          new NameValuePairs());

        Debug.println(response.toString());

        return response;
    }

    private String getID(String name, Hashtable<String, String> t) {
        Enumeration<String> keys = t.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String val = t.get(key);
            if (val.equals(name)) {
                return key;
            }
        }
        return "";
    }
}
