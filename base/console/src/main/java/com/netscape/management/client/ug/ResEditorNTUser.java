/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.ug;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.BitSet;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Observable;
import java.util.Observer;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import com.netscape.management.client.components.TimeDayPanel;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.ADUtil;
import com.netscape.management.client.util.AbstractDialog;
import com.netscape.management.client.util.DateTimePicker;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.nmclf.SuiOptionPane;


/**
 * ResEditorNTUser is a plugin for the ResourceEditor. It is used
 * when editing NT user information.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */

public class ResEditorNTUser extends JPanel implements IResourceEditorPage, ActionListener, Observer {
    public static String _NT_OBJECTCLASS="ntuser";
    public static String _NT_USER_DOMAIN_ID="ntuserdomainid";
    public static String _NT_USER_CREATE_NEW_ACCOUNT="ntusercreatenewaccount";
    public static String _NT_USER_DELETE_ACCOUNT="ntuserdeleteaccount";
    public static String _NT_USER_HOME_DIR="ntuserhomedir";
    public static String _NT_USER_COMMENT="ntusercomment";
    public static String _NT_USER_SCRIPT_PATH="ntuserscriptpath";
    public static String _NT_USER_WORKSTATIONS="ntuserworkstations";
    public static String _NT_USER_ACCT_EXPIRED="ntuseracctexpires";
    public static String _NT_USER_LOGON_HOUR="ntuserlogonhours";
    public static String _NT_USER_LOGON_SERVER="ntuserlogonserver";
    public static String _NT_USER_PROFILE="ntuserprofile";
    public static String _NT_USER_HOME_DIR_DRIVE="ntuserhomedirdrive";
    public static String _NT_USER_PRIV="ntuserpriv";
    public static String _NT_USER_FLAGS="ntuserflags";
    public static String _NT_USER_AUTH_FLAGS="ntuserauthflags";
    public static String _NT_USER_USR_COMMENT="ntuserusrcomment";
    public static String _NT_USER_PARMS="ntuserparms";
    public static String _NT_USER_LAST_LOGON="ntuserlastlogon";
    public static String _NT_USER_LAST_LOGOFF="ntuserlastlogoff";
    public static String _NT_USER_ACCT_EXPIRES="ntuseracctexpires";
    public static String _NT_USER_MAX_STORAGE="ntusermaxstorage";
    public static String _NT_USER_UNITS_PER_WEEK="ntuserunitsperweek";
    public static String _NT_USER_BAD_PW_COUNT="ntuserbadpwcount";
    public static String _NT_USER_NUM_LOGONS="ntusernumlogons";
    public static String _NT_USER_COUNTRY_CODE="ntusercountrycode";
    public static String _NT_USER_CODE_PAGE="ntusercodepage";
    public static String _NT_USER_UNIQUE_ID="ntuseruniqueid";
    public static String _NT_USER_PRIMARY_GROUP_ID="ntuserprimarygroupid";
    public static String _NT_USER_PASSWORD_EXPIRED="ntuserpasswordexpired";
    public static String _NT_UNIQUE_ID="ntUniqueId";

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    boolean    _enableModified; // A flag if _cbEnable was modified

    JCheckBox  _cbEnable;
    JTextField _tfDomainName;
    JCheckBox  _cbCreateAccount;
    JCheckBox  _cbDeleteAccount;
    JTextField _tfComment;
    JTextField _tfProfile;
    JTextField _tfScript;
    JComboBox  _cbDrive;
    JTextField _tfHomeDir;
    JTextField _tfLogonServer;
    JButton    _bLogonHour;
    JTextField _tfWorkstationList;
    JLabel     _lAccountExpired;
    JButton    _bExpiredDate;

    String _oldDomainName;
    boolean _fCreateAccount;
    boolean _fDeleteAccount;
    String _oldComment;
    String _oldProfile;
    String _oldScript;
    String _oldDrive;
    String _oldHomeDir;
    String _oldLogonServer;
    String _oldLogonHour;
    String _newLogonHour;
    String _oldWorkstationList;
    String _oldExpiredDate;
    String _newExpiredDate;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    private Vector componentVector = new Vector();

    ResourceEditor _resourceEditor;

    ConsoleInfo _info;

    ResourcePageObservable _observable;

    /**
     * Used to notify the ResourcePageObservable when a value has changed.
     * Note that this updates all observers.
     */
    FocusAdapter _focusAdaptor = new FocusAdapter() {
        public void focusLost(FocusEvent e) {

            // 550649 Chinese locale: If a focus is lost because the
            // window is no more active, do not update observable. Do it
            // only when another components in the same window gets focus.
            Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, ResEditorNTUser.this);
            if(w != null && w.getFocusOwner() == null) {
                return;
            }

            if (_observable == null) {
                return;
            }
            Component src = e.getComponent();
            if (src == _tfDomainName) {
                _observable.replace(_NT_USER_DOMAIN_ID, _tfDomainName.getText());
            } else if (src == _tfComment)
            {
                _observable.replace(_NT_USER_COMMENT, _tfComment.getText());
            } else if (src == _tfProfile)
            {
                _observable.replace(_NT_USER_PROFILE, _tfProfile.getText());
            } else if (src == _tfScript)
            {
                _observable.replace(_NT_USER_SCRIPT_PATH, _tfScript.getText());
            } else if (src == _tfHomeDir)
            {
                _observable.replace(_NT_USER_HOME_DIR, _tfHomeDir.getText());
            } else if (src == _tfLogonServer)
            {
                _observable.replace(_NT_USER_LOGON_SERVER, _tfLogonServer.getText());
            } else if (src == _tfWorkstationList)
            {
                _observable.replace(_NT_USER_WORKSTATIONS, _tfWorkstationList.getText());
            }
        }
    };

    ActionListener enableActionListener = new ActionListener()
        {
            public void actionPerformed(ActionEvent ev)
            {
                _enableModified = true;

                boolean state = _cbEnable.isSelected();
                Enumeration e = componentVector.elements();
                while(e.hasMoreElements())
                {
                    JComponent c = (JComponent)e.nextElement();
                    c.setEnabled(state);
                }
            }
        };

    /**
     * Constructor
     */
    public ResEditorNTUser() {
        super(true);
    }


    /**
     * A utility method to make case-insensitive check for Vector containment.
     */
    private boolean containsIgnoreCase(Vector v, String s) {
        return (getElementIgnoreCase(v, s) != null);
    }

    /**
     * A utility method to get a case-insensitive Vector string element
     */
    private String getElementIgnoreCase(Vector v, String s) {
        for (int i=0; i < v.size(); i++) {
            String element = (String) v.elementAt(i);
            if (element.equalsIgnoreCase(s)) {
                return element;
            }
        }
        return null;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Initializes the page with context information. It will be called once
     * the page is added to resource editor.
     *
     * @param observable  the observable object
     * @param parent      the resource editor container
     */
    public void initialize(ResourcePageObservable observable,
                           ResourceEditor parent) {
        ID = _resource.getString("NTUserPage", "ID");
        _resourceEditor = parent;
        _observable = observable;
        _info = observable.getConsoleInfo();

        // create all the label
        JLabel infoLabel = new JLabel(_resource.getString("userPage","required"));
        JLabel nameLabel = new JLabel(_resource.getString("NTUserPage", "DomainName"),SwingConstants.RIGHT);
        JLabel CommentLabel = new JLabel(_resource.getString("NTUserPage", "comment"),SwingConstants.RIGHT);
        JLabel ProfileLabel = new JLabel(_resource.getString("NTUserPage", "profile"),SwingConstants.RIGHT);
        JLabel ScriptLabel = new JLabel(_resource.getString("NTUserPage", "script"),SwingConstants.RIGHT);
        JLabel HomeDriveLabel = new JLabel(_resource.getString("NTUserPage", "homedrive"),SwingConstants.RIGHT);
        JLabel HomeDirLabel = new JLabel(_resource.getString("NTUserPage", "homedir"),SwingConstants.RIGHT);
        JLabel LogonServerLabel = new JLabel(_resource.getString("NTUserPage", "logonserver"),SwingConstants.RIGHT);
        JLabel WksLabel = new JLabel(_resource.getString("NTUserPage", "wks"),SwingConstants.RIGHT);
        JLabel AccountExpiredLabel = new JLabel(_resource.getString("NTUserPage", "accountexpired"),SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering
        componentVector.addElement(infoLabel);
        componentVector.addElement(nameLabel);
        componentVector.addElement(CommentLabel);
        componentVector.addElement(ProfileLabel);
        componentVector.addElement(ScriptLabel);
        componentVector.addElement(HomeDriveLabel);
        componentVector.addElement(HomeDirLabel);
        componentVector.addElement(LogonServerLabel);
        componentVector.addElement(WksLabel);
        componentVector.addElement(AccountExpiredLabel);

        _tfDomainName = new JTextField();
        nameLabel.setLabelFor(_tfDomainName);
        _cbEnable = new JCheckBox(_resource.getString("NTUserPage","enable"));
        _cbCreateAccount = new JCheckBox(_resource.getString("NTUserPage","createAccount"));
        _cbDeleteAccount = new JCheckBox(_resource.getString("NTUserPage","deleteAccount"));
        _tfComment = new JTextField();
        CommentLabel.setLabelFor(_tfComment);
        _tfProfile = new JTextField();
        ProfileLabel.setLabelFor(_tfProfile);
        _tfScript = new JTextField();
        ScriptLabel.setLabelFor(_tfScript);
        _cbDrive  = new JComboBox();
        HomeDriveLabel.setLabelFor(_cbDrive);
        _tfHomeDir = new JTextField();
        HomeDirLabel.setLabelFor(_tfHomeDir);
        _tfLogonServer = new JTextField();
        LogonServerLabel.setLabelFor(_tfLogonServer);
        _bLogonHour = new JButton(_resource.getString("NTUserPage","logonhour"));
        _bLogonHour.setToolTipText(_resource.getString("NTUserPage","logonhour_tt"));
        _tfWorkstationList = new JTextField();
        _lAccountExpired = new JLabel();
        _bExpiredDate = new JButton(_resource.getString("NTUserPage","change"));
        _bExpiredDate.setToolTipText(_resource.getString("NTUserPage","change_tt"));
        componentVector.addElement(_tfDomainName);
        componentVector.addElement(_cbCreateAccount);
        componentVector.addElement(_cbDeleteAccount);
        componentVector.addElement(_tfComment);
        componentVector.addElement(_tfProfile);
        componentVector.addElement(_tfScript);
        componentVector.addElement(_cbDrive);
        componentVector.addElement(_tfHomeDir);
        componentVector.addElement(_tfDomainName);
        componentVector.addElement(_bLogonHour);
        componentVector.addElement(_tfWorkstationList);
        componentVector.addElement(_lAccountExpired);
        componentVector.addElement(_bExpiredDate);

        _cbEnable.addActionListener(enableActionListener);
        _tfDomainName.addFocusListener(_focusAdaptor);
        _tfComment.addFocusListener(_focusAdaptor);
        _tfProfile.addFocusListener(_focusAdaptor);
        _tfScript.addFocusListener(_focusAdaptor);
        _tfHomeDir.addFocusListener(_focusAdaptor);
        _tfLogonServer.addFocusListener(_focusAdaptor);
        _tfWorkstationList.addFocusListener(_focusAdaptor);

        _bLogonHour.addActionListener(this);
        _bExpiredDate.addActionListener(this);

        JPanel p = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(p, _cbEnable, 0, 0, GridBagConstraints.REMAINDER, 1, 0.0,
                              0.0, GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        GridBagUtil.constrain(p, nameLabel, 0, 1, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfDomainName, 1, 1,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, _cbCreateAccount, 1, 2, GridBagConstraints.REMAINDER, 1, 0.0,
                              0.0, GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        GridBagUtil.constrain(p, _cbDeleteAccount, 1, 3, GridBagConstraints.REMAINDER, 1, 0.0,
                              0.0, GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        GridBagUtil.constrain(p, CommentLabel, 0, 4, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfComment, 1, 4,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, ProfileLabel, 0, 5, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfProfile, 1, 5,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, ScriptLabel, 0, 6, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfScript, 1, 6,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, HomeDriveLabel, 0, 7, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _cbDrive, 1, 7,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, HomeDirLabel, 0, 8, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfHomeDir, 1, 8,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, LogonServerLabel, 0, 9, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfLogonServer, 1, 9,
                              1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, _bLogonHour, 2, 9,
                              1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, WksLabel, 0, 10, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfWorkstationList, 1, 10,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, AccountExpiredLabel, 0, 11, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _lAccountExpired, 1, 11,
                              1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(p, _bExpiredDate, 2, 11,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, infoLabel, 1, 12,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, blankLabel, 0, 13,
                              GridBagConstraints.REMAINDER,
                              GridBagConstraints.REMAINDER, 1.0, 1.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        JScrollPane sp = new JScrollPane(p);
        sp.setBorder(null);

        setLayout(new BorderLayout());
        add("Center", sp);

        // set the value
        Vector valueVector = observable.get("objectclass");
        _cbEnable.setSelected(!containsIgnoreCase(valueVector, _NT_OBJECTCLASS));
        _cbEnable.doClick();
        _enableModified = false;

        _oldDomainName = observable.get(_NT_USER_DOMAIN_ID, 0);
        _tfDomainName.setText(_oldDomainName);

        String sTmp = observable.get(_NT_USER_CREATE_NEW_ACCOUNT,0);
        _fCreateAccount = Boolean.valueOf(sTmp.toLowerCase()).booleanValue();
        if (_fCreateAccount)
        {
            _cbCreateAccount.setSelected(true);
        }

        sTmp = observable.get(_NT_USER_DELETE_ACCOUNT,0);
        _fDeleteAccount = Boolean.valueOf(sTmp.toLowerCase()).booleanValue();
        if (_fDeleteAccount)
        {
            _cbDeleteAccount.setSelected(true);
        }

        _oldComment = observable.get(_NT_USER_COMMENT,0);
        _tfComment.setText(_oldComment);

        _oldProfile = observable.get(_NT_USER_PROFILE,0);
        _tfProfile.setText(_oldProfile);

        _oldScript = observable.get(_NT_USER_SCRIPT_PATH,0);
        _tfScript.setText(_oldScript);

        _oldDrive = observable.get(_NT_USER_HOME_DIR_DRIVE,0);
        for (char c='C';c<='Z';c++)
        {
            Character tmpC = Character.valueOf(c);
            _cbDrive.addItem(tmpC.toString());
        }
        _cbDrive.setSelectedItem(_oldDrive);
        if (_oldDrive == null || _oldDrive.length() == 0) {
            _oldDrive = (String)_cbDrive.getSelectedItem();
        }

        _oldHomeDir = observable.get(_NT_USER_HOME_DIR,0);
        _tfHomeDir.setText(_oldHomeDir);

        _oldLogonServer = observable.get(_NT_USER_LOGON_SERVER,0);
        _tfLogonServer.setText(_oldLogonServer);

        byte bLogonHour[]= observable.getBytes(_NT_USER_LOGON_HOUR);
        _oldLogonHour = convertBitToString(bLogonHour);
        _newLogonHour = _oldLogonHour;

        _oldWorkstationList = observable.get(_NT_USER_WORKSTATIONS,0);
        _tfWorkstationList.setText(_oldWorkstationList);

        _oldExpiredDate = observable.get(_NT_USER_ACCT_EXPIRED,0);
        Date dt = ADUtil.convertToJavaDateTime(_oldExpiredDate);
        if (ADUtil.neverExpires(dt)) {
            _lAccountExpired.setText(_resource.getString("resourceEditor", "NeverExpires"));
        } else if (dt != null) {
            _lAccountExpired.setText(dt.toString());
        } else {
            _lAccountExpired.setText("");
        }
        _newExpiredDate = _oldExpiredDate;
    }

    private String convertBitToString(byte b[])
    {
        String sReturn="";
        if (b!=null)
        {
            for (int i=0;i<168;i++)
            {
                int iByte = i/8;
                byte iPos = (byte)(1<<(i % 8));
                sReturn+=((b[iByte]&iPos)==0)?"0":"1";
            }
        }
        return sReturn;
    }

    public byte[] convertStringToBit(String s)
    {
        byte b[] = new byte[s.length()];
        for (int i=0;i<s.length();i++)
        {
            int iByte = i/8;
            byte iPos = (byte)(1<<(i % 8));
            b[iByte]|=(s.charAt(i)=='0')?0:iPos;
        }
        return b;
    }

    private BitSet convertStringToBitSet(String s)
    {
        BitSet b = new BitSet(168);

        for (int i=0;i<s.length();i++)
        {
            if (s.charAt(i)=='1')
            {
                b.set(i);
            }
        }
        return b;
    }

    private String convertBitSetToString(BitSet b)
    {
        String s = "";

        int size = 168;

        for (int i=0;i<size;i++)
        {
            s+=(b.get(i)?"1":"0");
        }
        return s;
    }

    class TimeDayDialog extends AbstractDialog {
        TimeDayPanel tp;

        int NUM_HOURS = 24;
        int NUM_DAYS  = 7;

        public TimeDayDialog(JFrame parent, BitSet bs) {
            super(parent, "", true, OK | CANCEL);

            getContentPane().setLayout(new GridBagLayout());
            tp = new TimeDayPanel();
            tp.selectAll(); //have to do select all, if not layout will get screw up.
            GridBagUtil.constrain(getContentPane(), tp, 0, 0,
                                  GridBagConstraints.REMAINDER, GridBagConstraints.REMAINDER,
                                  1.0, 1.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                                  0, 0, 0, 0);

            //getContentPane().add(tp);
            super.pack();
            tp.selectNone(); //unselect all to counter the select all above
            Debug.println(convertBitSetToString(bs));
            setSelectedTime(bs);
        }

        public String getBitSetString() {

            BitSet bset = new BitSet(NUM_HOURS*NUM_DAYS);
            int day[] = tp.getDaySelection();
            int hour[] = tp.getHourSelection();
            for (int i=0; i<day.length; i++) {
                for (int j=0; j<hour.length; j++) {
                    bset.set((day[i]*NUM_HOURS)+hour[j]);
                }
            }

            return convertBitSetToString(bset);
        }

        public void setSelectedTime(BitSet bs) {
            for (int i=0; i<bs.length(); i++) {
                if (bs.get(i)) {
                    int day = i/NUM_HOURS;
                    tp.addDaySelection(day, day);

                    int hour = i % NUM_HOURS;
                    tp.addHourSelection(hour, hour);
                }
            }
        }
    }


    public void actionPerformed(ActionEvent e)
    {
        if (e.getSource()==_bLogonHour)
        {
            // _logon hour
            BitSet bs = convertStringToBitSet(_newLogonHour);
            TimeDayDialog td = new TimeDayDialog(UtilConsoleGlobals.getActivatedFrame(), bs);
            td.show();
            if (!(td.isCancel())) {
                // set bit set
                _newLogonHour = td.getBitSetString();
                Debug.println("New logon hour: " + _newLogonHour);
            }

        } else if (e.getSource()==_bExpiredDate)
        {
            // expire date
            Date dt = ADUtil.convertToJavaDateTime(_newExpiredDate);
            Calendar c = Calendar.getInstance();
            if (!ADUtil.neverExpires(dt) && (dt != null)) {
                c.setTime(dt);
            }
            DateTimePicker picker = new DateTimePicker(UtilConsoleGlobals.getActivatedFrame(),c);
            picker.show();
            if (!picker.isCancel())
            {
                c = picker.getCalendar();
                dt = c.getTime();
                _newExpiredDate = ADUtil.convertToFileTime(dt);
                _lAccountExpired.setText(dt.toString());
            }
        }
    }

    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
        if ((o instanceof ResourcePageObservable) == false) {
            return;
        }
        ResourcePageObservable observable = (ResourcePageObservable) o;
        if (arg instanceof String) {
            String argString = (String) arg;
            if (argString.equalsIgnoreCase(_NT_USER_DOMAIN_ID)) {
                _tfDomainName.setText(observable.get(_NT_USER_DOMAIN_ID, 0));
            } else if (argString.equalsIgnoreCase(_NT_USER_CREATE_NEW_ACCOUNT)) {
                String sTmp = observable.get(_NT_USER_DELETE_ACCOUNT,0);

                boolean fCreateAccount = Boolean.valueOf(sTmp.toLowerCase()).booleanValue();
                if (fCreateAccount)
                {
                    _cbCreateAccount.setSelected(true);
                }
            } else if (argString.equalsIgnoreCase(_NT_USER_DELETE_ACCOUNT))
            {
                String sTmp = observable.get(_NT_USER_DELETE_ACCOUNT,0);

                boolean fDeleteAccount = Boolean.valueOf(sTmp.toLowerCase()).booleanValue();
                if (fDeleteAccount)
                {
                    _cbDeleteAccount.setSelected(true);
                }
            } else if (argString.equalsIgnoreCase(_NT_USER_COMMENT)) {
                String sTmp = observable.get(_NT_USER_COMMENT,0);
                _tfComment.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_PROFILE)) {
                String sTmp = observable.get(_NT_USER_PROFILE,0);
                _tfProfile.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_SCRIPT_PATH)) {
                String sTmp = observable.get(_NT_USER_SCRIPT_PATH,0);
                _tfScript.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_HOME_DIR_DRIVE)) {
                String sTmp = observable.get(_NT_USER_HOME_DIR_DRIVE,0);
                _cbDrive.setSelectedItem(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_HOME_DIR)) {
                String sTmp = observable.get(_NT_USER_HOME_DIR,0);
                _tfHomeDir.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_LOGON_SERVER)) {
                String sTmp = observable.get(_NT_USER_LOGON_SERVER,0);
                _tfLogonServer.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_LOGON_HOUR)) {
                String sTmp = observable.get(_NT_USER_LOGON_HOUR,0);
                _oldLogonHour = sTmp;
                _newLogonHour = sTmp;
            } else if (argString.equalsIgnoreCase(_NT_USER_WORKSTATIONS)) {
                String sTmp = observable.get(_NT_USER_WORKSTATIONS,0);
                _tfWorkstationList.setText(sTmp);
            } else if (argString.equalsIgnoreCase(_NT_USER_ACCT_EXPIRED)) {
                String sTmp = observable.get(_NT_USER_ACCT_EXPIRED,0);
                _lAccountExpired.setText(sTmp);
                _oldExpiredDate = sTmp;
                _newExpiredDate = sTmp;
            }
        }
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Returns unique ID string which identifies the page.
     *
     * @return  unique ID for the page
     */
    public String getID() {
        return ID;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Handle some post save condition. This is called after the
     * information is saved and the object has been created in
     * the directory server.
     *
     * @param observable     the observable object
     * @return               true if save succeeded; false otherwise
     * @exception Exception
     */
    public boolean afterSave(ResourcePageObservable observable)
              throws Exception {
                  return true;
              }

    /**
     * Implements the IResourceEditorPage interface.
     * Saves all modified information to the observable object
     *
     * @param observable     the observable object
     * @return               true if save succeeded; false otherwise
     * @exception Exception
     */
    public boolean save(ResourcePageObservable observable) throws Exception
    {
        String sDomainName=_tfDomainName.getText();
        String sComment   =_tfComment.getText();
        String sProfile   =_tfProfile.getText();
        String sScript   =_tfScript.getText();
        String sDrive   =(String)_cbDrive.getSelectedItem();
        String sHomeDir   =_tfHomeDir.getText();
        String sLogonServer   =_tfLogonServer.getText();
        //String sLogonHour   =_tfComment.getText();
        String sWorkstationList   =_tfWorkstationList.getText();
        //String sExpiredDate   =_tfComment.getText();

        if (!_enableModified) {
            ; // no changes for _cbEnable
        }
        else if(_cbEnable.isSelected())
        {
            Vector valueVector = observable.get("objectclass");
            if(!containsIgnoreCase(valueVector, _NT_OBJECTCLASS))
                valueVector.addElement(_NT_OBJECTCLASS);
            observable.replace("objectclass", valueVector);
        }
        else
        {
            Vector valueVector = observable.get("objectclass");
            if(containsIgnoreCase(valueVector, _NT_OBJECTCLASS))
                valueVector.removeElement(getElementIgnoreCase(valueVector, _NT_OBJECTCLASS));
            observable.replace("objectclass", valueVector);

            observable.delete(_NT_USER_DOMAIN_ID, "");
            observable.delete(_NT_USER_CREATE_NEW_ACCOUNT, "");
            observable.delete(_NT_USER_DELETE_ACCOUNT, "");
            observable.delete(_NT_USER_HOME_DIR, "");
            observable.delete(_NT_USER_COMMENT, "");
            observable.delete(_NT_USER_SCRIPT_PATH, "");
            observable.delete(_NT_USER_WORKSTATIONS, "");
            observable.delete(_NT_USER_ACCT_EXPIRED, "");
            observable.delete(_NT_USER_LOGON_HOUR, "");
            observable.delete(_NT_USER_LOGON_SERVER, "");
            observable.delete(_NT_USER_PROFILE, "");
            observable.delete(_NT_USER_HOME_DIR_DRIVE, "");
            observable.delete(_NT_USER_PRIV, "");
            observable.delete(_NT_USER_FLAGS, "");
            observable.delete(_NT_USER_AUTH_FLAGS, "");
            observable.delete(_NT_USER_USR_COMMENT, "");
            observable.delete(_NT_USER_PARMS, "");
            observable.delete(_NT_USER_LAST_LOGON, "");
            observable.delete(_NT_USER_LAST_LOGOFF, "");
            observable.delete(_NT_USER_ACCT_EXPIRES, "");
            observable.delete(_NT_USER_MAX_STORAGE, "");
            observable.delete(_NT_USER_UNITS_PER_WEEK, "");
            observable.delete(_NT_USER_BAD_PW_COUNT, "");
            observable.delete(_NT_USER_NUM_LOGONS, "");
            observable.delete(_NT_USER_COUNTRY_CODE, "");
            observable.delete(_NT_USER_CODE_PAGE, "");
            observable.delete(_NT_USER_UNIQUE_ID, "");
            observable.delete(_NT_USER_PRIMARY_GROUP_ID, "");
            observable.delete(_NT_USER_PASSWORD_EXPIRED, "");
            observable.delete(_NT_UNIQUE_ID, "");
            return true;
        }

        if (sDomainName.equals(_oldDomainName)==false)
        {
            observable.replace(_NT_USER_DOMAIN_ID,sDomainName);
        }

        if ((_fCreateAccount)&&(!_cbCreateAccount.isSelected()))
        {
            observable.replace(_NT_USER_CREATE_NEW_ACCOUNT,"false");
        } else if ((!_fCreateAccount)&&(_cbCreateAccount.isSelected()))
        {
            observable.replace(_NT_USER_CREATE_NEW_ACCOUNT,"true");
        }

        if ((_fDeleteAccount)&&(!_cbDeleteAccount.isSelected()))
        {
            observable.replace(_NT_USER_DELETE_ACCOUNT,"false");
        } else if ((!_fDeleteAccount)&&(_cbDeleteAccount.isSelected()))
        {
            observable.replace(_NT_USER_DELETE_ACCOUNT,"true");
        }

        if (sComment.equals(_oldComment)==false)
        {
            observable.replace(_NT_USER_COMMENT,sComment);
        }

        if (sProfile.equals(_oldProfile)==false)
        {
            observable.replace(_NT_USER_PROFILE,sProfile);
        }

        if (sScript.equals(_oldScript)==false)
        {
            observable.replace(_NT_USER_SCRIPT_PATH,sScript);
        }

        if (sDrive.equals(_oldDrive)==false)
        {
            observable.replace(_NT_USER_HOME_DIR_DRIVE,sDrive);
        }

        if (sHomeDir.equals(_oldHomeDir)==false)
        {
            observable.replace(_NT_USER_HOME_DIR,sHomeDir);
        }

        if (sLogonServer.equals(_oldLogonServer)==false)
        {
            observable.replace(_NT_USER_LOGON_SERVER,sLogonServer);
        }

        if (_newLogonHour.equals(_oldLogonHour)==false)
        {
            byte b[] = convertStringToBit(_newLogonHour);
            observable.replace(_NT_USER_LOGON_HOUR,b);
        }

        if (sWorkstationList.equals(_oldWorkstationList)==false)
        {
            observable.replace(_NT_USER_WORKSTATIONS,sWorkstationList);
        }

        if (_newExpiredDate.equals(_oldExpiredDate)==false)
        {
            observable.replace(_NT_USER_ACCT_EXPIRED,_newExpiredDate);
        }

        return true;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Clears all information on the page.
     */
    public void clear() {}

    /**
     * Implements the IResourceEditorPage interface.
     * Resets information on the page.
     */
    public void reset() {
        /*
           _groupName.setText("");
           _groupDescription.setText("");
         */
    }


    /**
     * Implements the IResourceEditorPage interface.
     * Sets default information on the page.
     */
    public void setDefault() {}

    /**
     * Implements the IResourceEditorPage interface.
     * Specifies whether any information on the page has been modified.
     *
     * @return  true if some information has been modified; false otherwise
     */
    public boolean isModified() {
        return _isModified;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Sets the modified flag for the page.
     *
     * @param value  true or false
     */
    public void setModified(boolean value) {
        _isModified = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Specifies whether the information on the page is read only.
     *
     * @return  true if some information has been modified; false otherwise
     */
    public boolean isReadOnly() {
        return _isReadOnly;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Sets the read only flag for the page.
     *
     * @param value  true or false
     */
    public void setReadOnly(boolean value) {
        _isReadOnly = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Sets the enabled flag for the page.
     *
     * @param value  true or false
     */
    public void setEnable(boolean value) {
        _isEnable = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Specifies whether all required information has been provided for
     * the page.
     *
     * @return  true if all required information has been provided; false otherwise
     */
    public boolean isComplete() {
        if (_cbEnable.isSelected() && _tfDomainName.getText().trim().length() == 0) {
            SuiOptionPane.showMessageDialog(null,
                                            _resource.getString("resourceEditor", "IncompleteText"),
                                            _resource.getString("resourceEditor",
                                                                "IncompleteTitle"), SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
            return false;
        }
        return true;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Returns a brief name for the page. The name should reflect the
     * plugin page.
     */
    public String getDisplayName() {
        return ID;
    }

    /**
     * Implements the IResourceEditorPage interface.
     * Displays help information for the page
     */
    public void help() {
        Help help = new Help(_resource);

        help.contextHelp("ug","ResEditorNTUser");
    }
}
