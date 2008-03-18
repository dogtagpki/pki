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

import java.util.*;
import java.text.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.misc.MessageFormatter;
import java.text.BreakIterator;
import java.text.Collator;
import com.netscape.management.nmclf.*;

/**
 * Utility class for the CMSAdmin package
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @date	 	01/12/97
 */
public class CMSAdminUtil {

    /*==========================================================
     * variables
     *==========================================================*/
    public static final int DEFAULT_TEXTFIELD_WIDTH = 30; 
    public static final int COMPONENT_SPACE = SuiLookAndFeel.COMPONENT_SPACE;
    public static final int SEPARATED_COMPONENT_SPACE = 
                                    SuiLookAndFeel.SEPARATED_COMPONENT_SPACE;
    public static final int DIFFERENT_COMPONENT_SPACE = 
                                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE;
    public static final int HELP_BUTTON_OFFSET = 9;         
    
    public static final int DEFAULT_BUTTON_SIZE = 72;
    
    final public static Dimension DEFAULT_PANEL_SIZE = new Dimension(350,440);
    final public static int DEFAULT_PADDING = SuiLookAndFeel.COMPONENT_SPACE;
    private static final int DEFAULT_WIDTH = 40;
    final public static Insets DEFAULT_EMPTY_INSETS = new Insets(0,0,0,0);
    public static final Insets DEAFULT_END_INSETS = new Insets(COMPONENT_SPACE,
                                COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE);
    
    public static final int WARNING_MESSAGE = JOptionPane.WARNING_MESSAGE;
    public static final int ERROR_MESSAGE = JOptionPane.ERROR_MESSAGE;
    public static final int INFORMATION_MESSAGE = JOptionPane.INFORMATION_MESSAGE;
    public static final int OK_OPTION = JOptionPane.OK_OPTION;
    public static final int NO_OPTION = JOptionPane.NO_OPTION;
    public static final int CANCEL_OPTION = JOptionPane.CANCEL_OPTION;
    
    private static Hashtable mPackageImages = new Hashtable();  //image container
    private static final ResourceSet mHelpResource =
      new ResourceSet("com.netscape.admin.certsrv.certsrv-help");
    public static final ResourceSet mResource =
      new ResourceSet("com.netscape.admin.certsrv.certsrv");
    public static Collator collator = Collator.getInstance();



    /*==========================================================
	 * Utilities methods
     *==========================================================*/
    
    /**
     * Utility function to retrieve images from the package image
     * class path.
     *
     * @param name Image name to be returned
     * @return Image
     */
    public static RemoteImage getImage( String name ) {
        String imageDir = CMSAdminResources.DEFAULT_IMAGE_DIRECTORY;
		RemoteImage i = (RemoteImage) mPackageImages.get( name );
		if ( i != null )
			return i;
        i = getSystemImage( imageDir + "/" + name );
		if ( i != null )
			mPackageImages.put( name, i );
		return i;
	}

    public static RemoteImage getThemeImage( String name ) {
        String imageDir = CMSAdminResources.DEFAULT_THEME_IMAGE_DIRECTORY;
		RemoteImage i = (RemoteImage) mPackageImages.get( name );
		if ( i != null )
			return i;
        i = getSystemImage( imageDir + "/" + name );
		if ( i != null )
			mPackageImages.put( name, i );
		return i;
	}

    /**
     * Utility function to reset the GridBagConstraints to default
     *
     * parameters specified below.
     * @param GridBagConstraints to be reseted
     */
    public static void resetGBC(GridBagConstraints gbc)
	{
      		gbc.gridx      = gbc.RELATIVE;
      		gbc.gridy      = gbc.RELATIVE;
      		gbc.gridwidth  = 1;
      		gbc.gridheight = 1;
      		gbc.fill       = gbc.HORIZONTAL;
      		gbc.anchor     = gbc.CENTER;
      		gbc.ipadx      = 0;
      		gbc.ipady      = 0;
      		gbc.weightx    = 0.0;
      		gbc.weighty    = 0.0;
      		gbc.insets     = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,COMPONENT_SPACE);
	}

    public static void repaintComp(JComponent component) {
        component.invalidate();
        component.validate();
        component.repaint(1);
    }

    public static void enableJTextField(JTextComponent component, 
      boolean enable, Color color) {
        component.setEnabled(enable);
        component.setEditable(enable);
        component.setBackground(color);
        component.invalidate();
        component.validate();
        component.repaint(1);
    }

    public static void addComponents(JPanel panel, JComponent comp1,
      JComponent comp2, GridBagConstraints gbc) {
        double weighty = gbc.weighty;
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        gbc.gridwidth = gbc.REMAINDER;
        panel.add(comp2, gbc);
    }

    public static void addComponents(JPanel panel, JComponent comp1,
      JComponent comp2, JComponent comp3, GridBagConstraints gbc) {
        double weighty = gbc.weighty;
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        gbc.gridwidth = gbc.REMAINDER;
        panel.add(comp3, gbc);
    }

    public static void addComponents(JPanel panel, JComponent comp1,
      JComponent comp2, JComponent comp3, JComponent comp4, 
      GridBagConstraints gbc) {
        double weighty = gbc.weighty;
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        panel.add(comp3, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = weighty;
        gbc.gridwidth = gbc.REMAINDER;
        panel.add(comp4, gbc);
    }

    /**
     * Add a label and a textfield to a panel, assumed to be using
     * GridBagLayout.
     */
    public static void addEntryField(JPanel panel, JComponent label, 
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field, gbc );
    }

    /**
     * Add 3 components in the same row to a panel, assumed to be using
     * GridBagLayout.
     */
    public static void addEntryField(JPanel panel, JComponent field1, 
      JComponent field2, JComponent field3, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field1, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(field2, gbc);

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field3, gbc );
    }
    
    /**
     * Add 4 components in the same row to a panel, assumed to be using
     * GridBagLayout.
     */
    public static void addEntryField(JPanel panel, JComponent field1, 
      JComponent field2, JComponent field3, JComponent field4, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field1, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 0.5;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(field2, gbc);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field3, gbc );
        
        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 0.5;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field4, gbc );
    }

    /**
     * Add 5 components in the same row to a panel, assumed to be using
     * GridBagLayout.
     */
    public static void addEntryField(JPanel panel, JComponent field1,
      JComponent field2, JComponent field3, JComponent field4,
      JComponent field5, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field1, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.HORIZONTAL;
        //gbc.weightx = 0.5;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(field2, gbc);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field3, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        //gbc.weightx = 0.5;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field4, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field5, gbc );
    }

    /**
     * Add 6 components in the same row to a panel, assumed to be using
     * GridBagLayout.
     */
    public static void addEntryField(JPanel panel, JComponent field1,
      JComponent field2, JComponent field3, JComponent field4,
      JComponent field5, JComponent field6, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field1, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.HORIZONTAL;
        //gbc.weightx = 0.5;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(field2, gbc);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field3, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        //gbc.weightx = 0.5;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add(field4, gbc);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx++;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( field5, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field6, gbc );
    }

    /**
     * Utility function to wrap text at given width. Used mostly
     * for displaying text in the dialog box.
     *
     * @param s message string
     * @param width width per line
     * @return string with line feeds
     */
    public static String wrapText(String str, int width)
    {
        if (str == null || str.length() < width) {
            return str;
        }
        String ret = "";

        StringTokenizer tokenizer = new StringTokenizer(str, "\n");
        while (tokenizer.hasMoreTokens()) {
        BreakIterator boundary = BreakIterator.getLineInstance();
        String s = (String)tokenizer.nextToken();
        boundary.setText(s);
        int end;
        int start = 0;
        while ((end = boundary.next()) != BreakIterator.DONE) {
            if (end - start > width) {
                end = boundary.previous();
                if (start == end) {
                    // Was too long for even one iteration
                    end = boundary.next();
                }
                ret += s.substring(start, end);
                ret += "\n";
                start = end;
            }
        }
        end = boundary.last();
        ret = ret+s.substring(start, end)+"\n";
        }
        return ret;
    }
    
    public static String certRequestWrapText(String s, int width) {
        String ret = "";
        StringTokenizer tokenizer = new StringTokenizer(s, "\n");
        int numTokens = tokenizer.countTokens();
        int index = 1;
        String beginCert = "";
        String endCert = "";
        String content = "";
        while(tokenizer.hasMoreTokens()) {
            String sToken = (String)tokenizer.nextToken();       
            if (index == 1) {
                beginCert = sToken;
            } else if (index == numTokens) {
                endCert = sToken;
            } else {
                content += sToken;
            }

            index++;
        }

        ret = beginCert+"\n"+wrapText(content, width, true)+"\n"+endCert;
        return ret;
    }

    public static String wrapText(String s, int width, boolean noIterator) {
        if (noIterator) {
            if (s == null || s.length() <= width) {
                return s;
            }

            String ret = "";
            int start = 0;
            int end = width;
            int len = s.length();
            while (len > width) {
                ret += s.substring(start, end);
                ret += "\n";
                len -= width;
                start += width;
                end += width;
            }
            ret += s.substring(start);
            return ret;
        } else {
            return wrapText(s, width);
        }
    }

    /**
     * Utility function to wrap text at default width. Used mostly
     * for displaying text in the dialog box.
     *
     * @param s message string
     * @return string with line feeds
     */
    public static String wrapText(String s) {
        return(wrapText(s, DEFAULT_WIDTH));
    }

    /**
     * Find out the table width to be used
     * 
     * @table JTable object
     */
    public static int getTotalColumnWidth( JTable table ) {
		Enumeration en = table.getColumnModel().getColumns();
		int width = 0;
		while( en.hasMoreElements() ) {
			TableColumn col = (TableColumn)en.nextElement();
			width += col.getWidth();
		}
		return width - 200;
	}


    /*==========================================================
     * Component Factory
     *==========================================================*/
     
    //==== BORDER CREATION ====================================
    public static Border makeEtchedBorder() {
        Border margin = new EmptyBorder(0,0,
                            SuiLookAndFeel.VERT_WINDOW_INSET,0);
        return new CompoundBorder(BorderFactory.createEtchedBorder(), margin);        
    }
    
    public static Border makeTitledBorder(ResourceBundle resource,
                                          String panelName,
                                          String keyword) {
        String title;
        try {
            title = resource.getString(panelName+"_BORDER_"+keyword+"_LABEL");
        } catch (MissingResourceException e) {
            title = "Missing Title";
        }
        return new TitledBorder(title);
    }
     
    //==== DIALOG CREATION ====================================    
    
    public static void showMessageDialog(ResourceBundle resource,
                                         String panelName,
                                         String keyword, 
                                         int messageType ) {
        showMessageDialog(UtilConsoleGlobals.getActivatedFrame(), resource, panelName, keyword, messageType);                                            
    }
     
    public static void showMessageDialog(JFrame frame,
                                         String title, 
                                         String msg, 
                                         int messageType ) {
        Icon icon;
        if (messageType != ERROR_MESSAGE)
            icon = getImage(CMSAdminResources.IMAGE_INFO_ICON);    
        else
            icon = getImage(CMSAdminResources.IMAGE_ERROR_ICON);
            
        JOptionPane.showMessageDialog(
                    frame,
                    CMSAdminUtil.wrapText(msg),
                    title, 
                    messageType, 
                    icon);
    }

    /**
     * Creating message dialog box for display
     */
    public static void showMessageDialog(JFrame frame,
                                         ResourceBundle resource,
                                         String panelName,
                                         String keyword, 
                                         int messageType ) {
        String msg, title;
        try {
            msg = resource.getString(panelName+"_DIALOG_"+keyword+ "_MESSAGE");
        } catch (MissingResourceException e) {
            msg = "Missing Label";
        }
        try {
            title = resource.getString(panelName+"_DIALOG_"+keyword+ "_TITLE");
        } catch (MissingResourceException e) {
            title = "Missing Title";
        }
        
        Icon icon;
        if (messageType != ERROR_MESSAGE)
            icon = getImage(CMSAdminResources.IMAGE_INFO_ICON);    
        else
            icon = getImage(CMSAdminResources.IMAGE_ERROR_ICON);
            
        JOptionPane.showMessageDialog(
                    frame,
                    CMSAdminUtil.wrapText(msg),
                    title, 
                    messageType, 
                    icon);
    }
    
    public static void showErrorDialog(ResourceBundle resource, 
                                       String message,
                                       int messageType) {                                        
        showErrorDialog(new JFrame(), resource, message, messageType);                                        
    }
    
    /**
     * Creating error dialog box for display
     */
    public static void showErrorDialog(JFrame frame,
                                       ResourceBundle resource, 
                                       String message,
                                       int messageType) {
        String title;
        try {
            title = resource.getString(CMSAdminResources.GENERAL_ERROR);
        } catch (MissingResourceException e) {
            title = "Missing Title";
        }
        JOptionPane.showMessageDialog(
                    frame,
                    CMSAdminUtil.wrapText(message),
                    title, 
                    messageType, 
                    getImage(CMSAdminResources.IMAGE_ERROR_ICON));
    }
   
    public static int showConfirmDialog( ResourceBundle resource,
                                         String panelName,
                                         String keyword, 
                                         int messageType ) 
    {
        return showConfirmDialog(new JFrame(), resource, panelName, keyword, messageType);    
    }
    
    public static int showConfirmDialog( ResourceBundle resource,
                                         String panelName,
                                         String keyword, String[] params,
                                         int messageType )
    {
        return showConfirmDialog(new JFrame(), resource, panelName, keyword,
          params, messageType);
    }

    /**
     * Creating confirm dialog box for display
     */    
    public static int showConfirmDialog( JFrame frame,
                                         ResourceBundle resource,
                                         String panelName,
                                         String keyword, 
                                         int messageType ) 
    {
        String msg, title;
        try {
            msg = resource.getString(panelName+"_DIALOG_"+keyword+ "_MESSAGE");
        } catch (MissingResourceException e) {
            msg = "Missing Label";
        }
        try {
            title = resource.getString(panelName+"_DIALOG_"+keyword+ "_TITLE");
        } catch (MissingResourceException e) {
            title = "Missing Title";
        }
        
        return JOptionPane.showConfirmDialog(
                frame,
                CMSAdminUtil.wrapText(msg), title,
                JOptionPane.YES_NO_OPTION,
                messageType,
                getImage(CMSAdminResources.IMAGE_WARN_ICON));
    }      
    
    public static int showConfirmDialog(JFrame frame, ResourceBundle resource,
      String panelName, String keyword, String[] params, int messageType )
    {
        String msg, title;
        try {
            msg = resource.getString(panelName+"_DIALOG_"+keyword+ "_MESSAGE");
        } catch (MissingResourceException e) {
            msg = "Missing Label";
        }
        try {
            title = resource.getString(panelName+"_DIALOG_"+keyword+ "_TITLE");
        } catch (MissingResourceException e) {
            title = "Missing Title";
        }

        String finalmsg = msg;
        if (params != null && params.length > 0) {
            MessageFormat mf = new MessageFormat(msg);
            finalmsg = mf.format(params);
        }

        return JOptionPane.showConfirmDialog(
                frame,
                CMSAdminUtil.wrapText(finalmsg), title,
                JOptionPane.YES_NO_OPTION,
                messageType,
                getImage(CMSAdminResources.IMAGE_WARN_ICON));
    }
    
    //==== LABEL CREATION ================================
    
    /**
     * Factory Method to create LABEL using specified params
     */
    public static JLabel makeJLabel(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword,
                                       Icon icon)
    {
        return makeJLabel(resource, panelName, keyword, icon, -1);
    }
    
    
    /**
     * Factory Method to create LABEL using specified params
     */
    public static JLabel makeJLabel(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword,
                                       Icon icon,
                                       int alignment)
    {
        String title;
        try {
            title = resource.getString(panelName+"_LABEL_"+keyword+ "_LABEL");
        } catch (MissingResourceException e) {
            title = "Missing Label";
            Debug.println("CMSAdminUtil - makeJLabel() - missing resource: "+panelName+"_LABEL_"+keyword+ "_LABEL");
        }
        JLabel label = new JLabel();
        if (icon != null)
            label.setIcon(icon);
        if (title != null)
            label.setText(title);
        if (alignment != -1)
            label.setHorizontalAlignment(alignment);    
        //setToolTip(resource, panelName, "LABEL_"+keyword, label);
        
        return label;
    }     
    
    
    //==== TEXTFIELD CREATION ================================
    
    /**
     * Factory Method to create TextFiled using specified params
     */
    public static JTextField makeJTextField(Document d, 
                                    String s, 
                                    int len,
                                    Object listener) {
                                        
        JTextField pf = new JTextField(DEFAULT_TEXTFIELD_WIDTH){ 
            public void setEnabled( boolean enabled ) {
                super.setEnabled( enabled );
                //super.setEditable(enabled);
                super.setBackground( enabled ? Color.white: SystemColor.window);
            } 
        }; 
        pf.setEnabled( true ); 
        
        if (d != null)
            pf.setDocument(d);
        if (s != null)
            pf.setText(s);
        if (len != -1)
            pf.setColumns(len);

        pf.addActionListener((ActionListener)listener);
        //detect text changes
        pf.getDocument().addDocumentListener((DocumentListener)listener);  
        return pf;
    }     
    
    //==== PASSWORD FIELD CREATION ================================
    
    /**
     * Factory Method to create Password Filed using specified params
     */
    public static JPasswordField makeJPasswordField(Document d, 
                                    String s, 
                                    int len,
                                    Object listener) {
        JPasswordField pf = new JPasswordField(DEFAULT_TEXTFIELD_WIDTH) {
            public void setEnabled( boolean enabled ) {
                super.setEnabled( enabled );
                super.setEditable(enabled);
                setBackground( enabled ? Color.white: SystemColor.window);
                this.repaint();
            } 
        }; 
        pf.setEnabled( true );
        if (d != null)
            pf.setDocument(d);
        if (s != null)
            pf.setText(s);
        if (len != -1)
            pf.setColumns(len);

        pf.addActionListener((ActionListener)listener);
        //detect text changes
        pf.getDocument().addDocumentListener((DocumentListener)listener);  
        return pf;
    }    
    
    
    //==== LIST CREATION ================================
    
    /**
     * Factory Method to create a list box mode specified with specific
     * visible row count. Special cell renderer is used to display each cell.
     */
    public static JList makeJList(DefaultListModel listModel, int visibleCount) {
        JList listbox = new JList(listModel);
        listbox.setCellRenderer(new AttrCellRenderer());
        listbox.setSelectionModel(new DefaultListSelectionModel());
        listbox.setVisibleRowCount(visibleCount);
        if(listModel.size()!=0)
            listbox.setSelectedIndex(0);
        return listbox;
    }
       
    //===== CHECKBOX CREATION =======================
    
    /**
     * Factory Method to create CheckBox using specified params
     */
    public static JCheckBox makeJCheckBox(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword,
                                       Icon icon,
                                       boolean select,
                                       ActionListener listener)
    {
        String label;
        try {
            label = resource.getString(panelName+"_CHECKBOX_"+keyword+ "_LABEL");
        } catch (MissingResourceException e) {
            label = "Missing Label";
        }
        
        JCheckBox button = new JCheckBox();
        if (label != null)
            button.setText(label);
        if (icon != null)
            button.setIcon(icon);
        button.setSelected(select);
        button.addActionListener(listener);
        //setToolTip(resource, panelName, "CHECKBOX_"+keyword, button);
        
        return button;
    } 
    
    //===== RADIO BUTTON CREATION =======================
    
    /**
     * Factory Method to create Radio Button using specified params
     */
    public static JRadioButton makeJRadioButton(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword,
                                       Icon icon,
                                       boolean select,
                                       ActionListener listener)
    {
        String label;
        try {
            label = resource.getString(panelName+"_RADIOBUTTON_"+keyword+ "_LABEL");
        } catch (MissingResourceException e) {
            label = "Missing Label";
        }
        
        JRadioButton button = new JRadioButton();
        if (label != null)
            button.setText(label);
        if (icon != null)
            button.setIcon(icon);
        button.setSelected(select);
        button.addActionListener(listener);
        //setToolTip(resource, panelName, "RADIOBUTTON_"+keyword, button);
        
        return button;
    }        
    
    //===== BUTTON CREATION =======================
    
    /**
     * Factory Method to create Button using specified params
     */
    public static JButton makeJButton(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword,
                                       Icon icon,
                                       ActionListener listener)
    {
        String label;
        try {
            label = resource.getString(panelName+"_BUTTON_"+keyword+ "_LABEL");
        } catch (MissingResourceException e) {
            label = "Missing Label";
        }
        
        JButton button = new JButton();
        if (label != null)
            button.setText(label);
        if (icon != null)
            button.setIcon(icon);
        button.addActionListener(listener);
        //setToolTip(resource, panelName, "BUTTON_"+keyword, button);
        
        return button;
    }    
    
   /**
	 * Create a panel with horizontally arranged, equally sized buttons
	 * The buttons are aligned to the right in the panel (if it is
	 * stretched beyond the length of the buttons)
	 *
	 * @param buttons An array of buttons for the panel
	 * @param isHelp Help button is the last one so pat extra space
     * @param isConfig don't pat button
	 * @return A panel containing the buttons
	 */
	 
    public static JPanel makeJButtonPanel( JButton[] buttons) {
        return makeJButtonPanel(buttons, false, false);
    }
    
    public static JPanel makeJButtonPanel( JButton[] buttons, boolean isHelp) {
        return makeJButtonPanel(buttons, isHelp, false);
    } 	 
	 
    public static JPanel makeJButtonPanel( JButton[] buttons, boolean isHelp, boolean isConfig) {
		JButtonFactory.resize( buttons );
		JPanel buttonPanel = new JPanel();
		GridBagConstraints gbc = new GridBagConstraints();
		buttonPanel.setLayout(new GridBagLayout());
		gbc.fill = gbc.HORIZONTAL;
		gbc.weightx = 1.0;
		gbc.weighty = 0.0;
		gbc.gridwidth = 1;
		buttonPanel.add( Box.createGlue(), gbc );
		gbc.fill = gbc.NONE;
		gbc.weightx = 0;
		for( int i = 0; i < buttons.length; i++ ) {
			if ( i == buttons.length-1 ) {
				gbc.gridwidth = gbc.REMAINDER;
				if (isHelp)
				    buttonPanel.add( Box.createHorizontalStrut(HELP_BUTTON_OFFSET));
				else 
				    buttonPanel.add( Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE) );
		    }
			buttonPanel.add( buttons[i], gbc );
			if ( i < buttons.length-2 )    
		        buttonPanel.add( Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE) );
		}
		
	    JPanel p = new JPanel();
		p.setLayout( new BorderLayout() );
		p.add( "Center", buttonPanel );
		
		if(!isConfig) {
		    p.add( "South",
	            Box.createVerticalStrut(DIFFERENT_COMPONENT_SPACE) );   
		    p.add( "East",
			    Box.createHorizontalStrut(DIFFERENT_COMPONENT_SPACE) );	            
	    } else {
	        p.add( "South",
	            Box.createVerticalStrut(DIFFERENT_COMPONENT_SPACE-COMPONENT_SPACE) );   
	    }
		p.add( "North",
			   Box.createVerticalStrut(DIFFERENT_COMPONENT_SPACE) );
			   
		return p;
	}

   /**
	 * Create a panel with vertically arranged, equally sized buttons
	 * The buttons are aligned to the top in the panel (if it is
	 * stretched beyond the length of the buttons)
	 *
	 * @param buttons An array of buttons for the panel
	 * @return A panel containing the buttons
	 */
	public static JPanel makeJButtonVPanel( JButton[] buttons ) {
	    //JButtonFactory.resize( buttons );
		JPanel buttonPanel = new JPanel();
		GridBagConstraints gbc = new GridBagConstraints();
		buttonPanel.setLayout(new GridBagLayout());
		resetGBC(gbc);
		gbc.fill = gbc.NONE;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.weightx = 1.0;
		gbc.insets = new Insets(0, DIFFERENT_COMPONENT_SPACE, 0,0);
		
		for( int i = 0; i < buttons.length; i++ ) {
			if ( i == buttons.length-1 )
				gbc.gridheight = gbc.REMAINDER;
			buttonPanel.add( buttons[i], gbc );
			gbc.insets = new Insets(COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
      		                            0, 0);
		}	    
	    
	    JPanel p = new JPanel();
		p.setLayout( new BorderLayout() );
		p.add( "Center", buttonPanel );			   
		return p;	    
	}
	 
    //===== COMBOBOX CREATION =======================
    
    public static JComboBox makeJComboBox(ResourceBundle resource, 
                                       String panelName, 
                                       String keyword)
    {
        String value = null;
        try {
            value = resource.getString(panelName+"_COMBOBOX_"+keyword+"_DEFAULT");
        } catch (MissingResourceException e) {
        }
        JComboBox jcb = new JComboBox();
        String val = null;
        int ii = 0;
        do {
            try {
                val = resource.getString(panelName+"_COMBOBOX_"+keyword+"_VALUE_"+ii);
                if (val != null) {
                    jcb.addItem(val);
                }
                ++ii;
            } catch (MissingResourceException e) {
                val = null;
            }   
        } while (val != null);
        
        if (value != null)
            jcb.setSelectedItem(value);
        return jcb;
    }
    
    
    //===== TOOL TIP CREATION =======================
    
    /**
     * Set tool tip on compoenent using resources passed in
     */
    public static void setToolTip(ResourceBundle resource, 
                            String panelName, 
                            String compKeyword, 
                            JComponent w) 
    {
        try {
            String ttip = resource.getString(panelName+"_"+compKeyword+"_TTIP");
            w.setToolTipText(ttip);
        } catch (MissingResourceException e) {
            //DON'T HAVE TOOT TIP
        }   
    }
    
    public static String[] randomize(String [] t) {
        String[] s = new String[t.length];
        System.arraycopy(t,0,s,0,t.length);
        String[] result = new String[s.length];

        int j=0;
        java.util.Random r = new java.util.Random();

        for (int i=0; i<s.length; i++) {
                int x = r.nextInt();
                if (x <0) x = -x;
                int n = x % (s.length-i);
                result[j] = s[n];
                s[n] = s[s.length-i-1];
                j++;
        }
        return result;
    }

	/**
	 * Sorts the array of strings using bubble sort.
	 * @param str The array of string being sorted. The str parameter contains
	 * the sorted result.
	 */
    public static void bubbleSort(String[] str) {
		for (int i = 0; i < str.length-1; i++) {
			for (int j = i+1; j < str.length; j++) {
                if( collator.compare(str[i], str[j]) > 0 ) {
					String t = str[i];
					str[i] = str[j];
					str[j] = t;
				}
			}
		}
	}    

    public static void bubbleSort(String[] str, String[] data) {
        for (int i = 0; i < str.length-1; i++) {
            for (int j = i+1; j < str.length; j++) {
                if( collator.compare(str[i], str[j]) > 0 ) {
                    String t = str[i];
                    str[i] = str[j];
                    str[j] = t;
                    String d = data[i];
                    data[i] = data[j];
                    data[j] = d;
                }
            }
        }
    }

    public static void quickSort(String[] str, int low, int high) {
        if (low >= high)
            return;

        String pivot = str[low];
        int slow = low-1, shigh = high+1;

        while (true) {
            do
            shigh--;
            while (collator.compare(str[shigh], pivot) > 0);
                do
                slow++;
            while (collator.compare(pivot, str[slow]) > 0);
                if (slow >= shigh)
                    break;

            String temp = str[slow];
            str[slow] = str[shigh];
            str[shigh] = temp;
        }

        quickSort (str, low, shigh);
        quickSort (str, shigh+1, high);
    }

    public static void help(String token) {
        Debug.println( "CMSAdminUtil.help: "+token);
        new Help(mHelpResource).help(token);
    }

    //get localized string using the format
    public static String getLocalizedString(ResourceBundle resource, 
                                            String keyword, 
                                            Object param) {
        return MessageFormatter.getLocalizedString(resource.getClass().getName(),
                                                   keyword, param);                                             
    }    
    
    //get localized string using the format
    public static String getLocalizedString(ResourceBundle resource, 
                                            String keyword, 
                                            Object [] params) {
        return MessageFormatter.getLocalizedString(resource.getClass().getName(),
                                                   keyword, params);                                             
    }
    
    public static String getPureString(String data) {
        StringBuffer input = new StringBuffer(data);
        StringBuffer buff = new StringBuffer();
        for (int i=0; i< input.length(); i++) {
            char c = input.charAt(i);
            if ((c != '\n') && (c != '\r'))
                buff.append(c);
        }
        return buff.toString();
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

	/**
	 * This is not necessary any more, now that RemoteImage implements
	 * the code we used to have inside this method.
	 */
    static RemoteImage getSystemImage( String imagePath ) {
		return new RemoteImage( imagePath );
    }
    
    public static JTextArea createTextArea(String str, Color color) {
        JTextArea desc = new JTextArea(str);
        desc.setBackground(color);
        desc.setEditable(false);
        desc.setCaretColor(color);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
 
        return desc;
    }

    public static long hexToLong(String s)
      throws NumberFormatException {
        int len = s.length();
        double y = 0;
        double base = 16;
        long num = 0;

        StringBuffer buffer = new StringBuffer(s);

        for (int i=0; i<len; i++) {
            char x = buffer.charAt(i);
            if (x >= '0' && x <= '9') {
                y = x-48;
            } else if (x == 'a') {
                y = 10;
            } else if (x == 'b') {
                y = 11;
            } else if (x == 'c') {
                y = 12;
            } else if (x == 'd') {
                y = 13;
            } else if (x == 'e') {
                y = 14;
            } else if (x == 'f') {
                y = 15;
            } else {
                num = -1;
                break;
            }
            num = num+(long)(y*Math.pow(base, len-1-i));
        }

        return num;
    }

    public static Object createTableCell(String syntax, String syntaxVal, String v) {
        if (syntax.equalsIgnoreCase("string") ||
          syntax.equalsIgnoreCase("integer")) {
            if (v == null) {
                return new JTextField("");
            } else {
                return new JTextField(v);
            }
        } else if (syntax.equalsIgnoreCase("choice")) {
            if (syntaxVal != null && syntaxVal.length() > 0) {
                StringTokenizer st = new StringTokenizer(syntaxVal, ",");
                int num = st.countTokens();
                String[] item = new String[num];
                int i=0;
                while (st.hasMoreTokens()) {
                    String token = st.nextToken();
                    // Fixes Bugscape Bug #56335:  remove extraneous ';'
                    if( token.charAt(0) == ';' ) {
                        token = token.substring(1);
                    }
                    item[i++] = token;
                }

                CMSAdminUtil.bubbleSort(item);
                JComboBox b = new JComboBox(item);

                if (v != null && v.length() > 0)
                    b.setSelectedItem(v);
                else
                    b.setSelectedIndex(0);
                return b;
            }
        } else if (syntax.equalsIgnoreCase("boolean")) {
            String[] item = {"true", "false"};
            JComboBox b = new JComboBox(item);
            if (v != null && v.equalsIgnoreCase("true")) {
                b.setSelectedIndex(0);
            } else {
                b.setSelectedIndex(1);
            }
            return b;
        }

        return null;
    }
}
