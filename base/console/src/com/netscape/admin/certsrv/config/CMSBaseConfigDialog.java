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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import javax.swing.text.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Plugin Parameter Configuration Dialog
 *
 * @author Steve Parkinson
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSBaseConfigDialog extends JDialog
    implements ActionListener, MouseListener, FocusListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    protected JFrame mParentFrame;
	protected ResourceBundle mResource;

	protected String PREFIX = null;

    protected boolean mIsOK = false;
    protected NameValuePairs mData=null;

    protected JScrollPane mScrollPane=null;
    protected JTable mTable=null;
    protected String mRuleName=null;//instance name
	protected JPanel mParamPanel=null;
	protected JPanel mHelpPanel=null;
	protected JTextArea mHelpLabel=null;

    protected JButton mOK=null, mCancel=null, mHelp=null;
    protected JTextField mPluginName=null;
    protected JLabel mImplnameCaption=null,mRulenameCaption=null;
    protected JLabel mImplName=null, mPluginLabel=null;
    protected String RAHELPINDEX=null;
    protected String KRAHELPINDEX=null;
    protected String CAHELPINDEX=null;
    protected String mHelpToken=null;

	protected AdminConnection mAdminConnection = null;

	protected String mImplName_token=null;//nvp index for plubinName
	protected String mImplType=null;//plugin type:policy,auth etc
	protected String mDest;
	protected String mInstanceScope=null;
    protected String mId = null;    // used as a ip id for crl exts

	/* true if creating a new instance
	 * false if editing an old one
     */
	protected boolean mNewInstance=false;  //

	private ExtendedPluginInfoSet mEPIs = null;
	protected CMSBaseResourceModel mModel = null;

    private String mServletName;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseConfigDialog(JFrame frame,
			String dest) {
        super(frame,true);
        mServletName = dest;
    }

    protected void init(NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest)
    {
        mParentFrame = parent;
		mDest = dest;
		mAdminConnection = conn;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(360, 415);

        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(mParentFrame);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    protected void init(NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest,
            String id)
    {
        mId = id;
        init(nvp, parent, conn, dest);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

	/**
	 * the model needs to be set if we need to start/stop the progress
	 * bar.
	 */

	public void setModel(CMSBaseResourceModel model)
	{
		mModel = model;
	}

	public void setInstanceScope(String s)
	{
		mInstanceScope = s;
	}

	/**
	 * retrieve the extended plugin information for this plugin
	 * from the server. The servlet must implement the scope
	 * 'extendedPluginInfo' and the plugin must implement the
	 * IExtendedPluginInfo interface, or else the display
	 * will revert back to simple name-value pairs.
	 */

	ExtendedPluginInfoSet getExtendedPluginInfo(String implname,
			NameValuePairs oldstyle) {

		NameValuePairs data = new NameValuePairs();
		String query = mImplType+":"+implname;//implName:pluginName
        NameValuePairs response=null;

		if (mImplType.equals("policy") &&
			(mRuleName != null) && !mRuleName.trim().equals("")) {
			query = query + ":" + mRuleName;
		}

	/* make the request to the server */
		try {
        	response = mAdminConnection.read(mServletName,
                               ScopeDef.SC_EXTENDED_PLUGIN_INFO,
                               query,
                               data);
		}
		catch (EAdminException e) {
		}

		ExtendedPluginInfoSet epis = new ExtendedPluginInfoSet();

		if (response == null) response = new NameValuePairs();

	/* if the servlet or rule wasn't capable of handling the new style
	 * of interface, just return the names from the name/value pairs that
	 * were passed in
	 * otherwise, for each parameter name, fetch the associated
	 * parameter type from the extendedPluginInfo that the server
	 * returned
	 */
		for (String name : oldstyle.keySet()) {
			String value = response.get(name);
			if (value != null) {
				epis.add(name, value,false);
			}
			else {
				epis.add(name, "",true);
			}
		}


		String ht = response.get("HELP_TOKEN");
		if (ht != null) epis.setHelpToken(ht);

		String hs = response.get("HELP_TEXT");
		if (hs != null) epis.setHelpSummary(hs);

		return epis;
	}



    /**
     * show the list of configuration parameters
     */
    public void showDialog(NameValuePairs data, String name) {
        mIsOK = false;

        mData = data;

		Debug.println("in CMSBaseConfigDialog.showDialog()");

		JPanel p = mParamPanel;
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        p.setLayout(gb);

		mRuleName = data.get(mImplName_token);
		mEPIs = getExtendedPluginInfo(mRuleName,data);

        for (String entry : data.keySet()) {
		entry = entry.trim();
		Debug.println("in CMSBaseConfigDialog.showDialog() entry=" + entry);
           	if (!entry.equals(mImplName_token)) {
				String labelname = entry;

				/* comp is the component which represents the value
				 * of the parameter. It can be a checkbox, choice, or
				 * text field
				 */

				JComponent comp = null;
		String stringvalue = data.get(entry);
				ExtendedPluginInfo epi = mEPIs.get(entry);
				if (epi == null) {
					Debug.println("no ExtendedPluginInfo for "+entry);
				}

				if (epi.getType() == ExtendedPluginInfo.TYPE_PASSWORD) {
					labelname = "password";
				}

				if (epi.isRequired()) {
					labelname = "* "+labelname;
				}

				/* this label is the name of the parameter. We need
				 * to add a mouselistener so that we can update the
				 * help text if someone clicks on the label
				 */
				JLabel l = new JLabel(labelname);
				l.addMouseListener(this);

				CMSAdminUtil.resetGBC(gbc);

				gbc.gridwidth = 1;
				gbc.fill = gbc.NONE;
				gbc.weightx = 0.2;
				gbc.gridwidth = 1;
				gbc.anchor = gbc.EAST;
				gbc.insets = new Insets(
					CMSAdminUtil.COMPONENT_SPACE, // top
					0,  // left
					0,	// bottom
					5); // right
				p.add(l,gbc);


				/* if there was no text extendedplugininfo for this parameter
				 * just make it a text box
				 */
				if (epi == null) {
					comp = new JTextField(stringvalue);
				}
				else  {
					epi.setValue(stringvalue);
					comp = epi.makeComponent(this);
				}

				/* this lets us get an event when this component
				 * is clicked on, so we can update the help text
				 */
				comp.addFocusListener(this);

				gbc.weightx = 0.7;
				gbc.fill = gbc.HORIZONTAL;
				gbc.gridwidth = gbc.RELATIVE;
				gbc.anchor = gbc.WEST;
				gbc.insets = new Insets(
						CMSAdminUtil.COMPONENT_SPACE, //top
						0,              			  //left
						0, //bottom
						0); // right
				p.add(comp ,gbc);

				/* add a dummy component to the end of each row to
				 * keep it from hiting the edge of the panel
				 */
				JLabel j = new JLabel("");
				gbc.weightx = 0.1;
				gbc.fill = gbc.HORIZONTAL;
				gbc.gridwidth = gbc.REMAINDER;
				gbc.anchor = gbc.WEST;
				gbc.insets = new Insets(
						CMSAdminUtil.COMPONENT_SPACE,  //top
						0,  //left
						0,  //bottom
						CMSAdminUtil.COMPONENT_SPACE); // right
				p.add(j,gbc);

           	}
       	}

        mImplName.setText(mRuleName);

        if ((name==null)||name.equals("")) {
			mNewInstance = true;
            /* we're dealing with a new instance - so the rule name is
			 * a text box - it's editable
			 */
            mPluginName.setVisible(true);
            mPluginName.setText(getDefaultInstanceName(mRuleName));
            mPluginLabel.setVisible(false);
        } else {
			mNewInstance = false;
            /* we're editing an old instance - so the rule name is just
			 * a label - you can't edit it
			 */
            mPluginName.setVisible(false);
            mPluginLabel.setVisible(true);
            mPluginLabel.setText(name);
        }

		mHelpLabel.setText(mEPIs.getHelpSummary());
		mHelpLabel.repaint();

		mImplName.addMouseListener(this);
		mPluginName.addMouseListener(this);
		mPluginLabel.addMouseListener(this);

        this.show();
    }

	public String getDefaultInstanceName(String implName)
	{
		Debug.println("in CMSBaseConfigDialog::getDefaultInstanceName("+implName+") - returning ''");
		return "";
	}

    public boolean isOK() {
        return mIsOK;
    }


    public String getRuleName() {
        return mRuleName;
    }

    /*==========================================================
	 * EVENT HANDLER METHODS
     *==========================================================*/

	/**
	 * From focuslistener interface. This lets us know when a component
	 * has received focus, so we can update the help text.
	 */
	public void focusGained(FocusEvent f) {
		Component comp = f.getComponent();
		mPluginName.addFocusListener(this);
		mPluginLabel.addMouseListener(this);
		String text = "";

		if (comp instanceof ExtendedPluginInfoComponent) {
			ExtendedPluginInfoComponent epic = (ExtendedPluginInfoComponent)comp;
			ExtendedPluginInfo epi = epic.getExtendedPluginInfo();
			text = epi.getHelpText()+" ";
		}
		else if (doHelpSummary(comp)) {
			text = mEPIs.getHelpSummary();
		}
		else {
		}

		mHelpLabel.setText(text);
		mHelpLabel.repaint();

	}

	/** need to supply this method for focuslistener, but we
	 * really don't care about it
	 */
	public void focusLost(FocusEvent f) {
	}


	/*
	 * mouselistener events - for JLabel
	 */

	/**
	 * This lets us know when someone clicked a label, so we can
	 * update the help text
	 */
	public void mouseClicked(MouseEvent e) {
		Component c = e.getComponent();
		String helpText = "";
		if (c instanceof JLabel) {
			String paramName = ((JLabel)c).getText();
			ExtendedPluginInfo epi = mEPIs.get(paramName);

			if (epi != null) helpText = epi.getHelpText();
			else if (doHelpSummary(c)) {
				helpText = mEPIs.getHelpSummary();
			}
		}
		mHelpLabel.setText(helpText);
		mHelpLabel.repaint();
	}

	public void mouseEntered(MouseEvent e) {
	}
	public void mouseExited(MouseEvent e) {
	}
	public void mousePressed(MouseEvent e) {
	}
	public void mouseReleased(MouseEvent e) {
	}


	public boolean doHelpSummary(Component c) {

		if (c.equals(mPluginName) ||
			c.equals(mPluginLabel) ||
			c.equals(mRulenameCaption) ||
			c.equals(mImplnameCaption) ||
			c.equals(mImplName) )  {
			return true;
		}
		else {
			return false;
		}
	}

    //=== ACTIONLISTENER =====================

	/**
	 *  this gets called when a someone made some kind of event happen.
	 *  We really only check for the OK, Cancel, or Help buttons here
	 */
	public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {

		/* if  this is a new instance of a rule, (as opposed to editing an old one) */
            if (mNewInstance) {
                mRuleName = mPluginName.getText();
		/* make sure they set the name of the rule, otherwise, show an error message */
                if (mRuleName.trim().equals("")) {
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        mResource.getString("INSTANCECONFIGDIALOG_DIALOG_NOINSTANCENAME_MESSAGE"),
                        CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
            }
			else {
				mRuleName = mPluginLabel.getText();
			}

			Debug.println(4,"User pressed okay on instance config dialog");
			Enumeration e = mEPIs.keys();
			NameValuePairs nvp = new NameValuePairs();
			while (e.hasMoreElements()) {
				String paramName = (String)e.nextElement();
				ExtendedPluginInfo epi = mEPIs.get(paramName);
				String value = epi.getComponentStateAsString();
				if (epi.getType() == ExtendedPluginInfo.TYPE_PASSWORD) {
					String password = value;
					value = "Rule "+mRuleName;
					if (password != null && password.length() >0) {
						nvp.put("PASSWORD_CACHE_ADD", value + ";" + password);
					}
				}

				nvp.put(paramName, value);
			}
			nvp.put(PolicyRuleDataModel.RULE_NAME, mRuleName);
			nvp.put(mImplName_token, mImplName.getText());

			mData = nvp;
			try {
				if (mModel != null) { mModel.progressStart(); }
				if (mNewInstance == true) {
					mAdminConnection.add(mDest, mInstanceScope, mRuleName, nvp);
				}
				else {
                    if (mId != null && mId.length() > 0) {
                        nvp.put(Constants.PR_ID, mId);
                    }
					mAdminConnection.modify(mDest, mInstanceScope, mRuleName, nvp);
				}
           		mIsOK = true;
				if (mModel != null) { mModel.progressStop(); }
           		this.dispose();
			}
			catch (EAdminException ex) {
				mModel.progressStop();
				CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        ex.toString(),CMSAdminUtil.ERROR_MESSAGE);
			}
        }

        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mHelp)) {
			String ht = mEPIs.getHelpToken();
			if (ht == null || ht.equals("")) {
            	CMSAdminUtil.help(mHelpToken);
			}
			else {
				CMSAdminUtil.help(ht);
			}
        }
    }


	public NameValuePairs getData() {
		return mData;
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


        /* Content panel. This is where we put the name/value pairs,
		 * and the help text */
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.fill = gbc.BOTH;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
        gb.setConstraints(content, gbc);
		center.add(content);


		/* Action panel. This is where we put the OK, Cancel, Help buttons */
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

    //create botton action panel
    private JPanel makeActionPane() {

        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);

	//JButton[] buttons = { mOK, mCancel, mHelp};
	JButton[] buttons = { mOK, mCancel};
		JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    protected void setDestination(String dest) {
        mDest = dest;
    }

    protected JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

		/* mPluginName and mPluginLabel occupy the same space in the UI, but
		 * only one of them is visible at a time. showDialog() determines which
		 * is visible. If this is a new component, mPluginName is visible, and is a
		 * a text field, so the user can enter the name of the new instance.
		 * Otherwise, it's just a label, showing the existing name.
		 */
	// 'Policy Rule ID' here
        CMSAdminUtil.resetGBC(gbc);
        mRulenameCaption = CMSAdminUtil.makeJLabel(mResource, PREFIX,
            "RULENAME", null);
		mRulenameCaption.addMouseListener(this);
        mPluginLabel = new JLabel();
        mPluginLabel.setVisible(false);
        mPluginName = new JTextField();

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
		gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add(mRulenameCaption, gbc);

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
		gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
      		                     0,CMSAdminUtil.COMPONENT_SPACE);
        mListPanel.add( mPluginName, gbc );
        mListPanel.add( mPluginLabel, gbc );

	// 'Policy Plugin ID' here
        CMSAdminUtil.resetGBC(gbc);
        mImplnameCaption = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "IMPLNAME", null);
		mImplnameCaption.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mImplnameCaption, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mImplName = new JLabel();
        mListPanel.add( mImplName, gbc );

	/* Panel for list of plugin's parameters */
		mParamPanel = new JPanel();

		mScrollPane = new JScrollPane(mParamPanel);
		mScrollPane.setBorder(CMSAdminUtil.makeEtchedBorder());

		CMSAdminUtil.resetGBC(gbc);
		gbc.fill = gbc.BOTH;
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(mScrollPane, gbc);
		mListPanel.add(mScrollPane);

	/* Panel in which to put plugin's help text */
		mHelpPanel = new JPanel();
		mHelpPanel.setBorder(CMSAdminUtil.makeEtchedBorder());
        mHelpLabel = new JTextArea(3,0);
		mHelpLabel.setLineWrap(true);
		mHelpLabel.setWrapStyleWord(true);
		mHelpLabel.setBackground(mHelpPanel.getBackground());
		mHelpLabel.setEditable(false);
        GridBagLayout gb2 = new GridBagLayout();
        GridBagConstraints gbc2 = new GridBagConstraints();

		CMSAdminUtil.resetGBC(gbc2);
		gbc2.fill = gbc.BOTH;
        gbc2.anchor = gbc.WEST;
        gbc2.gridwidth = gbc.REMAINDER;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gb2.setConstraints(mHelpLabel, gbc2);
        mHelpPanel.setLayout(gb2);
		mHelpPanel.add(mHelpLabel);

		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.SOUTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gb.setConstraints(mHelpPanel, gbc);
		mListPanel.add(mHelpPanel);

        return mListPanel;
    }

}


class ExtendedPluginInfoSet extends Hashtable {

	/**
	 * Add a value for this config parameter.
	 * the format of 'syntax' is specified in
	 * @see com.netscape.certsrv.base.IExtendedPluginInfo
	 */
	public void add(String param, String syntax, boolean oldstyle) {

	  try {
		String type;
		ExtendedPluginInfo epi;
		boolean required=false;

		if (!oldstyle) {
			String rest, helptext;
			int semicolon = syntax.indexOf(';');

			type = syntax.substring(0,semicolon);
			rest = syntax.substring(semicolon+1);

			for (int i=0;i<1;i++) {
				int length = type.length();
				if (type.endsWith(",required")) {
					type=type.substring(0,length-0);
					required=true;
				}
			}
			helptext = rest; // ADDED to fix bug #383969
/*
			semicolon = rest.indexOf(';');
			if (semicolon == -1) {  // no more semicolons
				helptext = rest;
			}
			else {
				helptext = rest.substring(0,semicolon);
				rest = rest.substring(semicolon+1);
			 }
*/
			epi = new ExtendedPluginInfo(type,helptext);
			epi.setRequired(required);
		}
		else {
			epi = new ExtendedPluginInfo("string","");
		}

		put(param,epi);
	  } catch (Exception e) {
		Debug.println("Badly formatted ExtendedpluginInfo for string: '"+
			syntax+"'");
		}
	}

	private String mHelpSummary = "";
	private String mHelpToken = "";

	public String getHelpSummary() {
		return mHelpSummary;
	}

	public void setHelpSummary(String summary) {
		mHelpSummary = summary;
	}

	public String getHelpToken() {
		return mHelpToken;
	}

	public void setHelpToken(String token) {
		mHelpToken = token;
	}

	public ExtendedPluginInfo get(String param) {
		return (ExtendedPluginInfo)super.get(param);
	}

}



interface ExtendedPluginInfoComponent
{
	public abstract ExtendedPluginInfo getExtendedPluginInfo();

	public abstract String getValueAsString();
}


class ExtendedPluginInfoCheckBox extends JCheckBox
implements ExtendedPluginInfoComponent
{
	private ExtendedPluginInfo mEpi;

	public ExtendedPluginInfoCheckBox(ExtendedPluginInfo epi, boolean b)
	{
		super("",b);
		mEpi = epi;
	}

	public ExtendedPluginInfo getExtendedPluginInfo() {
		return mEpi;
	}

	public String getValueAsString() {
		if (isSelected()) {
			return "true";
		}
		else {
			return "false";
		}
	}

}

class ExtendedPluginInfoComboBox extends JComboBox
implements ExtendedPluginInfoComponent
{
	private ExtendedPluginInfo mEpi;

	public ExtendedPluginInfoComboBox(ExtendedPluginInfo epi, Vector v)
	{
		super(v);
		mEpi = epi;
	}

	public ExtendedPluginInfo getExtendedPluginInfo() {
		return mEpi;
	}

	public String getValueAsString() {
		return (String)getSelectedItem();
	}
}

class ExtendedPluginInfoTextField extends JTextField
implements ExtendedPluginInfoComponent
{
	private ExtendedPluginInfo mEpi;

	public ExtendedPluginInfoTextField(ExtendedPluginInfo epi, String s)
	{
		super(s);
		mEpi = epi;
	}

	public ExtendedPluginInfo getExtendedPluginInfo() {
		return mEpi;
	}

	public String getValueAsString() {
		return getText();
	}
}

class ExtendedPluginInfoPasswordField extends JPasswordField
implements ExtendedPluginInfoComponent
{
	private ExtendedPluginInfo mEpi;

	public ExtendedPluginInfoPasswordField(ExtendedPluginInfo epi, String s)
	{
		super(s);
		mEpi = epi;
	}

	public ExtendedPluginInfo getExtendedPluginInfo() {
		return mEpi;
	}

	public String getValueAsString() {
		return getText();
	}
}

class ExtendedPluginInfoNumberField extends JTextField
implements ExtendedPluginInfoComponent
{
	private ExtendedPluginInfo mEpi;

	public ExtendedPluginInfoNumberField(ExtendedPluginInfo epi, String s)
	{
		super(s);
		mEpi = epi;
	}

	public ExtendedPluginInfo getExtendedPluginInfo() {
		return mEpi;
	}

	public String getValueAsString() {
		return getText();
	}

	protected Document createDefaultModel() {
		return new NumberDocument();
	}

	static class NumberDocument extends PlainDocument {

      public void insertString(int offs, String str, AttributeSet a)
		throws BadLocationException {

		if (str == null) {
			return;
		}

		char[] chars = str.toCharArray();
		int j=0;

		for (int i = 0; i < chars.length; i++) {
			if ( (chars[i]<'0' || chars[i]>'9')
				&& (chars[i] != '.')
				&& (chars[i] != '-') ) {
			}
			else {
				chars[j++] = chars[i];
			}
		}
		char newchars[] = new char[j];
		if (j != 0) {
			System.arraycopy(chars,0,newchars,0,j);
		}
		super.insertString(offs, new String(newchars), a);
	  }
	}
}



/**
 * This class records information about the type of a parameter
 * and what possible value it can take
 */

class ExtendedPluginInfo {

	public static final int  TYPE_STRING = 0;
	public static final int  TYPE_BOOLEAN = 1;
	public static final int  TYPE_NUMBER = 2;
	public static final int  TYPE_CHOICE = 3;
	public static final int  TYPE_PASSWORD = 4;

	private int mType;
	private boolean mRequired;

	private String mValue = null;

	private Vector mChoices = null;

	private String mHelpText = null;


	ExtendedPluginInfo(String type, String helptext)
	{
		mHelpText = helptext;

		if (type.equals("string")) {
			mType = TYPE_STRING;
		}
		else if (type.equals("boolean")) {
			mType = TYPE_BOOLEAN;
		}
		else if (type.equals("number")) {
			mType = TYPE_NUMBER;
		}
		else if (type.equals("integer")) {
			mType = TYPE_NUMBER;
		}
		else if (type.equals("password")) {
			mType = TYPE_PASSWORD;
		}
		else if (type.startsWith("choice")) {
			mType = TYPE_CHOICE;
			String choices = type.substring(
				type.indexOf('(')+1,
				type.indexOf(')')
				);
			StringTokenizer tokenizer = new StringTokenizer(choices,",",false);
			mChoices = new Vector();
			String prefix = null;
			while (tokenizer.hasMoreElements()) {
				String c = (String)tokenizer.nextElement();
				int i = c.indexOf("\\");
				if ( i != -1 ) {
					if (prefix == null)
						prefix = c.substring(0,i);
					else
						prefix = prefix + "," + c.substring(0,i);
				} else {
					if (prefix != null) {
						c = prefix + "," + c;
						prefix = null;
					}
					mChoices.addElement(c);
				}
			}
		}
		else {
			mType = TYPE_STRING;   // unknown type - default to string type
		}
	}

	public Vector getChoices() {
		return mChoices;
	}

	public String getHelpText() {
		return mHelpText;
	}

	public String getValue() {
		return mValue;
	}

	public void setValue(String val) {
		mValue = val;
	}

	public int getType() {
		return mType;
	}

	public void setRequired(boolean b) {
		mRequired = b;
	}

	public boolean isRequired() {
		return mRequired;
	}

	private JComponent component = null;

	public JComponent getComponent() {
		return component;
	}

	public String getComponentStateAsString() {
		if (component == null)
			return null;
		return ((ExtendedPluginInfoComponent)component).getValueAsString();
	}

	public JComponent makeComponent(ActionListener al)
	{
		switch (getType()) {
			case ExtendedPluginInfo.TYPE_BOOLEAN:
				boolean b;
				if (getValue().equals("true")) { b=true; }
				else { b = false; }
				component = new ExtendedPluginInfoCheckBox(this,b);
				((ExtendedPluginInfoCheckBox)component).addActionListener(al);
				break;

			case ExtendedPluginInfo.TYPE_STRING:
				component = new ExtendedPluginInfoTextField(this,getValue());
				((ExtendedPluginInfoTextField)component).addActionListener(al);
				break;

			case ExtendedPluginInfo.TYPE_NUMBER:
				component = new ExtendedPluginInfoNumberField(this,getValue());
				((ExtendedPluginInfoNumberField)component).addActionListener(al);
				break;

			case ExtendedPluginInfo.TYPE_PASSWORD:
				component = new ExtendedPluginInfoPasswordField(this,"");
				((ExtendedPluginInfoPasswordField)component).addActionListener(al);
				break;

			case ExtendedPluginInfo.TYPE_CHOICE:
				JComboBox cb = new ExtendedPluginInfoComboBox(this,getChoices());
				cb.setSelectedItem(getValue());
				((ExtendedPluginInfoComboBox)cb).addActionListener(al);
				component = cb;
				break;

			default:
				return null;
		}
		return component;
	}

}
