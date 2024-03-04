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
package com.netscape.management.client.ace;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;

import netscape.ldap.*;

import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

/**
 * This modal dialog edits properties of a specific ACI.
 * It is used internally by the ACIManager.
 * 
 * The following tabs are predefined:
 * 1) Users and Groups
 * 2) Rights
 * 3) Target
 * 4) Host
 * 5) Time
 * 
 * Additional tabs may be registered at the following location:
 * cn=ACIEditor, ou=[Console Version], ou=Global Preferences, ou=[domain], o=NetscapeRoot
 * which is an entry of this type:
 *      objectclass nsAdminObject
 *          superior top
 *          requires
 *              cn
 *          allows
 *              nsJarFilename,
 *              nsClassName    
 * 
 * The nsClassName attribute can have multiple values of the
 * following syntax:
 * <code>classname@jarfilename@location</code>
 * Where classname is the package and class name that implements com.netscape.management.client.ace.IACITab
 *       jarfilename is the name of the jarfile that contains classname
 *       location is either a SIE entry or HTTP URL
 *       (for SIE entries, the url for the corresponding Admin Server is used)
 * 
 * For example:
 * <code>com.netscape.management.admserv.MyACITab@admserv50.jar@cn=admin-serv-cobalt, cn=Netscape Administration Server, cn=Server Group, cn=cobalt.mcom.com, ou=mcom.com, o=NetscapeRoot</code>
 * 
 */
class ACIEditor extends GenericDialog
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static ImageIcon warningIcon = new RemoteImage("com/netscape/management/client/images/warn16.gif");
    private static String KEYWORD_ACLNAME = "acl";
    private static String KEYWORD_VERSION = "version";
    private static String DEFAULT_VERSION = "3.0";
    private static String MANUAL_MODE = "MANUAL";
    private static String VISUAL_MODE = "VISUAL";
    private static String displayMode = VISUAL_MODE; // static to remember across invocations
    private static char ERASE_CHAR = '~';
    
    private String aciVersion = DEFAULT_VERSION;
    private Vector tabVector = new Vector();  // elements instanceof IACITabs
    private JTabbedPane tabbedPane = null;
    private JFrame parentFrame = null;
    private JTextArea aciNameField = new JTextArea(2,30);
    private LDAPConnection aciLdc;
    private LDAPConnection ugLdc;
    private String aciDN = null;
    private String currentACI = null;
    private String unusedACI = null;
    private String ugDN = null;
    private CardLayout panelCardLayout = null;
    private JPanel contentPanel = null;
    private JButton modeButton = null;
    private JTextArea textArea = null;
    private boolean isInitialized = false;
    private LDAPAttribute origACIAttr = null;

    private static String i18n(String id)
    {
        return i18n.getString("ed", id);
    }

    /**
     * This contructor is used to edit an existing ACI.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param aciLdc        a LDAP connection to server where ACIs reside
     * @param aciDN         a DN where ACIs reside
     * @param ugLdc         a LDAP connection to server where UGs reside
     * @param ugDN          a DN where Users and Groups reside
     * @param initialACI    a String containing the initial ACI value.
     */
    public ACIEditor(JFrame parentFrame, String title, LDAPConnection aciLdc, String aciDN, LDAPConnection ugLdc, String ugDN, String initialACI)
    {
        super(parentFrame, "", OK_CANCEL_HELP, HORIZONTAL);
        this.parentFrame = parentFrame;
        this.aciLdc = aciLdc;
        this.ugLdc = ugLdc;
        this.aciDN = aciDN;
        this.ugDN = ugDN;
        this.currentACI = initialACI;
        this.tabVector = createDefaultTabs();
		String formattedTitle = java.text.MessageFormat.format(i18n("title"), new Object[] { title });
        setTitle(formattedTitle);
    }
    
    public void show()
    {
        if(!isInitialized)
        {
            isInitialized = true;
            tabVector = orderTabs(tabVector);
            if(currentACI == null || currentACI.length() == 0)
                displayMode = VISUAL_MODE;
            setButtonComponent(createButtonPanel());
            contentPanel = createContentPanel();
            String newMode = displayMode;
            displayMode = "";
            setDisplayMode(newMode, false);
            getContentPane().add(contentPanel);
            setMinimumSize(getPreferredSize());
        }
        super.show();
    }
    
    /**
     * @returns the edited ACI string.
     */
    public String getACI()
    {
        String aci = createACI();
        StringBuffer cleanACI = new StringBuffer();
        int length = aci.length();
        for(int i = 0; i < length; i++)
            if(aci.charAt(i) != '\n')
                cleanACI.append(aci.charAt(i));
        return cleanACI.toString();
    }
    
    private String createACI()
    {
        String result;
        if(getDisplayMode().equals(VISUAL_MODE))
        {
		    StringBuffer aci = createACI(new StringBuffer());
            Enumeration e = tabVector.elements();
            while(e.hasMoreElements())
            {
                IACITab tab = (IACITab)e.nextElement();
                aci = tab.createACI(aci);
            }
            result = aci.toString();
        }
        else
        {
            result = textArea.getText();
        }
        Debug.println("ACI: " + result);
        return result;
    }
    
    /**
     * Returns the number of ACI tabs that will be shown
     * in the ACI Editor dialog.
     * 
     * @return count of tabs in ACI Editor
     */
    public int getACITabCount()
    {
        return tabVector.size();
    }
    
    /**
     * Returns a tab object at the specified index.
     * 
     * @param index the number of the tab to return
     * @return the IACITab object at the specified index
     */
    public IACITab getACITab(int index)
    {
        return (IACITab)tabVector.elementAt(index);
    }
    
    /**
     * Adds a tab to the list of tabs that will be displayed in the ACI Editor.
     * The position of the tab is determined by its getPreferredPosition method.
     * 
     * @param tab the tab to be added to the ACI Editor tabbed pane.
     */
    public void addACITab(IACITab tab)
    {
        tabVector.addElement(tab);
    }
    
    /**
     * Removes a tab from the specified location in the list of
     * tabs that will be displayed in the ACI Editor.
     * 
     * @param index the number of the tab to be removed
     */
    public void removeACITab(int index)
    {
        tabVector.removeElementAt(index);
    }
    
	private Vector createDefaultTabs()
	{
        Vector v = new Vector();
        v.addElement(new UGTab());
        v.addElement(new RightsTab());
        v.addElement(new TargetTab());
        v.addElement(new HostTab());
        v.addElement(new TimeTab());
        // TODO: load tabs dynamically

        // points to NetscapeRoot\mcom.com\Global Preferences\Admin\<Console version>
        String baseDN = "cn=ACIEditor, " + LDAPUtil.getAdminGlobalParameterEntry();
        try
        {
            LDAPEntry entry = aciLdc.read(baseDN, new String[] { "nsClassName" });
            Debug.println("DN: " + entry.getDN());
            LDAPAttributeSet entryAttrs = entry.getAttributeSet();
            Enumeration attrsInSet = entryAttrs.getAttributes();
            while(attrsInSet.hasMoreElements())
            {
                LDAPAttribute nextAttr = (LDAPAttribute)attrsInSet.nextElement();
                String attrName = nextAttr.getName();
                Debug.println("\t" + attrName + ":");
                Enumeration valsInAttr = nextAttr.getStringValues();
                while(valsInAttr.hasMoreElements()) 
                {
                    String className = (String)valsInAttr.nextElement();
                    Debug.println("\t\t" + className);
                    ConsoleInfo ci = Console.getConsoleInfo();
                    Class c = ClassLoaderUtil.getClass(ci, className);
                    if(c.isInstance(IACITab.class))
                    {
                        v.addElement(c);
                    }
                }
            }
        } 
        catch (LDAPException e)
        {
            Debug.println("Cannot read tab extension DN: " + baseDN);
            Debug.println("LDAP exception code: " + e.getLDAPResultCode());
        }
        
        return v;
	}
    
    /**
     * Sort tabs by their preferred position
     */
    private Vector orderTabs(Vector unsortedTabs)
    {
        Vector orderedTabs = new Vector();
        for(int i = 0; i < 11; i++)
        {
            if(i == 10)
                i = -1;
            Enumeration e = unsortedTabs.elements();
            while(e.hasMoreElements())
            {
                IACITab tab = (IACITab)e.nextElement();
                if(tab.getPreferredPosition() == i)
                    orderedTabs.addElement(tab);
            }
            if(i == -1)
                i = 10;
        }
        return orderedTabs;
    }
    
    private JPanel createButtonPanel()
    {
        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, COMPONENT_SPACE);
        String modeButtonText;
        String modeButtonToolTipText;
        if(displayMode.equals(VISUAL_MODE)) {
            modeButtonText = i18n("manual");
            modeButtonToolTipText = i18n("manual_tt");
        } else {
            modeButtonText = i18n("visual"); 
            modeButtonToolTipText = i18n("visual_tt");
        }
        modeButton = ButtonFactory.createButton(modeButtonText, new ManualActionListener(), "CMD");
        modeButton.setToolTipText(modeButtonToolTipText);
        p.add(modeButton, gbc);
        
        return p;
    }

    private JPanel createContentPanel()
    {
        JPanel p = new JPanel();
        panelCardLayout = new CardLayout();
        p.setLayout(panelCardLayout);
        GridBagConstraints gbc = new GridBagConstraints();
        
        p.add(MANUAL_MODE, createManualPanel());
        p.add(VISUAL_MODE, createVisualPanel());
        
        return p;
    }
    
    private void setDisplayMode(String modeID, boolean showException)
    {
        if(modeID.equals(MANUAL_MODE))
        {
            if(displayMode.equals(VISUAL_MODE))
                currentACI = createACI();
            textArea.setText(currentACI);
        }
        else
        if(modeID.equals(VISUAL_MODE))
        {
            if(displayMode.equals(MANUAL_MODE))
                currentACI = textArea.getText();               

            try
            {
                ACIAttribute[] aciAttributes =
                     ACIAttribute.toArray(ACIParser.getACIAttributes(currentACI));
                 setVisualMode(aciAttributes);
                 if (aciAttributes.length > 0 && !checkVisualConversion(aciAttributes)) {
                     throw new Exception(i18n("visualUnsupported"));
                 }
            }
            catch (Exception e)
            {
                setDisplayMode(MANUAL_MODE, false);
                
                if (!showException)
                    return;
                
                String title = i18n("visualFailedTitle");
                String msgText = i18n("visualFailedMsg");
                String tipText = null;
                String detailText = e.getMessage();
                ErrorDialog err = new ErrorDialog(this, title, msgText, tipText, detailText,
                                  ErrorDialog.OK, ErrorDialog.OK);
                err.setVisible(true);
                return;
            }
        }
        panelCardLayout.show(contentPanel, modeID);
        displayMode = modeID;
        ButtonFactory.setButtonText(modeButton, (modeID == MANUAL_MODE ? i18n("visual") : i18n("manual")));
        modeButton.setToolTipText((modeID == MANUAL_MODE ? i18n("visual_tt") : i18n("manual_tt")));
    }

    private void setVisualMode(ACIAttribute[] aciAttributes) throws Exception
    {
        ACIAttribute[] usedAttributes;
        usedAttributes = aciChanged(aciAttributes, currentACI);        
        StringBuffer aciBuffer = new StringBuffer(currentACI);
        eraseACI(aciBuffer, usedAttributes);
        IACITab tab;
        Enumeration e = tabVector.elements();
        while(e.hasMoreElements())
        {
            tab = (IACITab)e.nextElement();
            usedAttributes = tab.aciChanged(aciAttributes, currentACI);
            eraseACI(aciBuffer, usedAttributes);
        }
        tab = (IACITab)tabVector.elementAt(tabbedPane.getSelectedIndex());
	    tab.tabSelected();
        if(aciAttributes.length > 0)
        {
            ACIAttribute lastAttr = aciAttributes[aciAttributes.length-1];
            int parseEndIndex = lastAttr.getEndIndex();
            if(parseEndIndex > 0)
                aciBuffer.setLength(parseEndIndex+1);
        }
        unusedACI = aciBuffer.toString();
    }

    private boolean equalStrings(String s1, String s2)
    {
            if (s1 != null)
            {
                return s1.equals(s2);
            }
            return (s2 == null);
    }


    /**
     * Verify that visual mode does not incorrectly modify the original ACI
     */
    private boolean checkVisualConversion(ACIAttribute[] attrOrig)
    {
        // unusedACI must contain only ~ chanracters
        if (unusedACI != null)
        {
            for (int i=0; i < unusedACI.length(); i++)
            {
                if (unusedACI.charAt(i) != ERASE_CHAR)
                {
                    Debug.println("ACIEditor.checkVisualConversion: conversion failed unusedACI="+unusedACI);
                    return false;
                }
            }
        }
        
        // Check if visual mode incorrectly converts the ACI
        
        String savedDisplayMode = displayMode;
        displayMode = VISUAL_MODE; // for getACI() to work
        String visualACI = getACI();
        displayMode = savedDisplayMode;
        
        ACIAttribute[] attrVisual =
            ACIAttribute.toArray(ACIParser.getACIAttributes(visualACI));
        
        if (attrOrig.length != attrVisual.length)
        {
            Debug.println("ACIEditor.checkVisualConversion: conversion failed, attr arrays size mismatch");
            return false;
        }
        
        for (int i=0; i<attrOrig.length; i++)
        {
            if (!equalStrings(attrOrig[i].getName(), attrVisual[i].getName()))
            {
                Debug.println("ACIEditor.checkVisualConversion: " +
                                   "conversion failed, attribute name mismatch " +
                                   attrOrig[i].getName() + " v.s. " + attrVisual[i].getName());
                return false;
            }
            if (!equalStrings(attrOrig[i].getOperator(), attrVisual[i].getOperator()))
            {
                Debug.println("ACIEditor.checkVisualConversion: " +
                                   "conversion failed for " + attrOrig[i].getName() +
                                   " operator mismatch " + attrOrig[i].getOperator() +
                                   " v.s. " + attrVisual[i].getOperator());

                return false;
            }
        }
        return true;
    }


    private static void eraseACI(StringBuffer b, ACIAttribute[] a)
    {
        if(a == null)
            return;
        
        for(int i = 0; i < a.length; i++)
        {
            eraseACI(b, a[i].getStartIndex(), a[i].getEndIndex());
        }
    }
    
    private static void eraseACI(StringBuffer b, int begin, int end)
    {
        for(int i = begin; i <= end; i++)
            b.setCharAt(i, ERASE_CHAR);
    }
    
    private String getDisplayMode()
    {
        return displayMode;
    }
    
    private JPanel createManualPanel()
    {
        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel label = new JLabel(i18n("manualLabel"));
        p.add(label, gbc);
        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        textArea = new JTextArea(4,30);
        textArea.setFont(FontFactory.getFont(FontFactory.FONT_MONOSPACED));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        p.add(new JScrollPane(textArea), gbc);

        gbc.gridx = 0;       gbc.gridy = 2;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        JLabel warningLabel = new JLabel(i18n("warning"), warningIcon, SwingConstants.LEFT);
        p.add(warningLabel, gbc);
        
        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        JButton syntaxButton = ButtonFactory.createButton(i18n("syntax"), new SyntaxActionListener(), "");
        syntaxButton.setToolTipText(i18n("syntax_tt"));
        p.add(syntaxButton, gbc);
        
        return p;
    }
        
    private JPanel createVisualPanel()
    {
        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, COMPONENT_SPACE);
        JLabel aciLabel = new JLabel();
        aciLabel.setText(i18n("aciLabel"));
        aciLabel.setLabelFor(aciNameField);
        p.add(aciLabel, gbc);
        
        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);

        aciNameField.setFont(FontFactory.getFont(FontFactory.FONT_MONOSPACED));
        aciNameField.setLineWrap(true);
        aciNameField.setWrapStyleWord(true);
        aciNameField.setBorder(UIManager.getBorder("TextField.border"));
        p.add(new JScrollPane(aciNameField), gbc);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        tabbedPane = createTabbedPane();
        p.add(tabbedPane, gbc);
        
        return p;
    }
    
    class SyntaxActionListener implements ActionListener
    {
        final String ACI_ALL = "(targetattr=\"*\")(version 3.0; acl \"Allow Everyone\"; allow (all) (userdn = \"ldap:///anyone\") ;)";
        final String ACL_PLUGIN_DN = "cn=ACL Plugin,cn=plugins,cn=config";

        public void actionPerformed(ActionEvent event)
        {
            LDAPAttribute oldACIAttr = null;
            LDAPAttribute testACIAttr = null;
            LDAPModification mod = null;
            Container parent = SwingUtilities.getAncestorOfClass(JDialog.class, contentPanel);

            try {
                ACIManager.testACI(aciLdc, aciDN, getACI());
                String title = i18n("syntaxPassedTitle");
                String msg = i18n("syntaxPassedMsg");
                JOptionPane.showMessageDialog(parent, msg, title, JOptionPane.INFORMATION_MESSAGE);
            }
            catch (LDAPException e)
            {
                String title = i18n("syntaxFailedTitle");
                String msg = i18n("syntaxFailedMsg");
                JOptionPane.showMessageDialog(parent, msg, title, JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    class ManualActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            String mode = getDisplayMode();
            if(mode.equals(VISUAL_MODE))
            {
                setDisplayMode(MANUAL_MODE, true);
            }
            else
            {
                setDisplayMode(VISUAL_MODE, true);
            }
        }
    }
    
    /**
     * Notification that the ACI has changed
     * This method is called in two situations:
     * 1) during initialization, after getComponent is called.
     * 2) after a change from manual to visual mode.
     * 
     * The tab implementation should examine the changed aci and return
     * all parsed ACIAttribute objects the tab recognized and processed.
     * The return value may be null if no attributes were recognized.
     * 
     * @param aciAttributes  the aci as an array of ACIAttribute objects
     * @param rawACI         the aci string
     * @return an array of ACIAttribute objects that were recognized
     * 
     * @see ACIParser#parseACI
     * @see ACIAttribute
     */
    public ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String aciString)
    {
        aciNameField.setText("");
        aciVersion = DEFAULT_VERSION;
        Vector usedAttributes = new Vector();
        ACIAttribute a = ACIAttribute.getAttribute(KEYWORD_ACLNAME, aciAttributes);
        if(a != null)
        {
            String value = a.getValue();
            aciNameField.setText(value);
            usedAttributes.addElement(a);
        }
        
        a = ACIAttribute.getAttribute(KEYWORD_VERSION, aciAttributes);
        if(a != null)
        {
            String value = a.getValue();
            aciVersion = value;
            usedAttributes.addElement(a);
        }
        return ACIAttribute.toArray(usedAttributes);
    }
    
    private JTabbedPane createTabbedPane() 
    {
        JTabbedPane tabbedPane = new JTabbedPane();
        Enumeration e = tabVector.elements();
        while(e.hasMoreElements())
        {
            IACITab tab = (IACITab)e.nextElement();
            tab.initialize(parentFrame, aciLdc, aciDN, ugLdc, ugDN);
            tabbedPane.addTab(tab.getTitle(), tab.getComponent());
        }
		tabbedPane.addChangeListener(new ChangeListener()
			{
				public void stateChanged(ChangeEvent e)
				{
					JTabbedPane tp = (JTabbedPane)e.getSource();
					int index = tp.getSelectedIndex();
                    IACITab tab = (IACITab)tabVector.elementAt(index);
					tab.tabSelected();
				}
			});
        return tabbedPane;
    }

    /**
     * Returns a new ACI that includes attributes from this tab.
     * This tab's attributes can be appended/prepended/inserted 
     * into the existingACI.
     * 
     * This method is called when in two situations:
     * 1) when the user presses OK in the ACIEditor dialog.
     * 2) after a change from visual to manual mode.
     * 
     * @param existingACI   the existing aci
     * @return the new aci that includes this tab's attributes
     */
    public StringBuffer createACI(StringBuffer existingACI)
	{
        String name = aciNameField.getText();
        if(name.length() == 0)
            name = i18n.getString("mgr", "nonameACI");

        existingACI.append("(" + KEYWORD_VERSION + " " + aciVersion + ";\n");
		existingACI.append(KEYWORD_ACLNAME + " \"" + name + "\";\n;)");
        if(unusedACI != null)
        {
            StringTokenizer st = new StringTokenizer(unusedACI, String.valueOf(ERASE_CHAR), false);
            while(st.hasMoreTokens())
            {
                String token = balanceParenthesis((String)st.nextToken()) + " ";
                if(existingACI.toString().endsWith("\n;)"))
                {
                    int len = existingACI.length() - 3;
                    existingACI.insert(len, token);
                }
            }
        }
        return existingACI;
	}
    
    private static String balanceParenthesis(String s)
    {
        int right = 0;
        int left = 0;
        for(int i = s.length()-1; i >= 0; i--)
        {
            if(s.charAt(i) == '(')
                left++;
            if(s.charAt(i) == ')')
                right++;
        }
        
        if(right > left)
            return balanceParenthesis("(" + s);
        
        if(left > right)
            return balanceParenthesis(s + ")");
        
        return s;
    }
	
    /**
     * Called when the Help button is pressed.
     */
    protected void helpInvoked() 
    {
        if(displayMode == VISUAL_MODE)
        {
            int i = tabbedPane.getSelectedIndex();
            if (i >= 0)
            {
                IACITab tab = (IACITab)tabVector.elementAt(i);
                tab.helpInvoked();
            }
        }
        else // Manual mode
        {
		    ConsoleHelp.showContextHelp("ace-manual");
        }
    }
}

