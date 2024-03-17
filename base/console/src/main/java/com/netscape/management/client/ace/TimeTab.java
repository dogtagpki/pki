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
import java.util.*;
import javax.swing.*;
import netscape.ldap.LDAPConnection;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

/**
 * This tab controls when this object can be accessed.
 * 
 * Reference:
 * http://docs.netscape.com/docs/manuals/directory/41/admin/acl.htm#998558
 * 
 * The LDIF syntax for setting a bind rule based on the day of the 
 * week is as follows: dayofweek = "<day>" 
 * where <day> is one of the following: Sun, Mon, Tue, Wed, Thu, Fri, Sat. 
 * A list of values is allowed.
 */
class TimeTab implements IACITab, UIConstants
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static String KEYWORD_TIMEOFDAY = "timeofday";
    private static String KEYWORD_DAYOFWEEK = "dayofweek";
    private static String KEYWORD_OR = "or";
    private static String KEYWORD_AND = "and";
	private static String[] DAYS = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    private static int TAB_POSITION = 4;
	private JPanel p = new JPanel();
	private boolean isInitialized = false;
	private TimeDayPanel timeDayPanel;
    
    private static String i18n(String id) 
    {
        return i18n.getString("time", id);
    }
    
    /**
     * Called once to provide global information about this
     * invocation of the ACIManager.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param aciLdc        a LDAP connection to server where ACIs reside
     * @param aciDN         a DN where ACIs reside
     * @param ugLdc         a LDAP connection to server where UGs reside
     * @param ugDN          a DN where Users and Groups reside
     */
    public void initialize(JFrame parentFrame, LDAPConnection aciLdc, String aciDN, LDAPConnection ugLdc, String ugDN)
    {
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
    public ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String rawACI)
    {
        Vector usedAttributes = new Vector();
        boolean hasDayOfWeek = false;
        timeDayPanel.selectNone();
        
        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_DAYOFWEEK))
            {
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
                hasDayOfWeek = true;
			    String days = a.getValue();
                if(days == null)
                    break;
                days = days.toLowerCase();
			    for(int x = 0; x < DAYS.length; x++)
			    {
                    String day = DAYS[x].toLowerCase();
			    	if(days.indexOf(day) != -1)
			    	{
			    		timeDayPanel.addDaySelection(x, x);
			    	}
			    }
            }
        }    

        if(hasDayOfWeek == false)
        {
            timeDayPanel.setDaySelection(0, 6);
        }
            
        /**
         * The timeofday keyword requires a time of day in the 24 hour clock (0 to 2359). 
         * Inequality expressions are allowed. The LDIF syntax for setting a bind rule 
         * based on the time of day is as follows:
         * timeofday <operator> "<time>" 
         * where <operator> is equal to (=), not equal to (!=), greater than (>), 
         * greater than or equal to (>=), less than (<), or less than or equal to (<=).
         */
        int lowerHour = 0;
        int upperHour = 23;
        
        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_TIMEOFDAY))
            {
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
				String time = a.getValue();
				if(time.length() == 4)
					time = time.substring(0, 2);
				else
				if(time.length() == 3)
					time = time.substring(0, 1);
				else
					break;

                int hour = -1;
                try
                {
				    hour = Integer.parseInt(time);
                }
                catch(NumberFormatException ex)
                {
                    Debug.println("TimeTab: " + ex);
                }
                if(hour < 0 || hour > 23)
                    break;
                
				String operator = a.getOperator();
				if(operator.equals("="))
				{
                    // TODO: not handled
					//timeDayPanel.addHourSelection(hour, hour);
				}
				else
				if(operator.equals("!="))
				{
                    // TODO: not handled
					//timeDayPanel.addHourSelection(0, hour-1);
					//timeDayPanel.addHourSelection(hour+1, 23);
				}
				else
				if(operator.equals(">"))
				{
					lowerHour = hour+1;
				}
				else
				if(operator.equals("<"))
				{
					upperHour = hour-1;
				}
				else
				if(operator.equals(">="))
				{
					lowerHour = hour;
				}
				else
				if(operator.equals("<="))
				{
					upperHour = hour;
				}
			}
		}
        timeDayPanel.setHourSelection(lowerHour, upperHour);
        return ACIAttribute.toArray(usedAttributes);
    }
        
    /**
     * Retrieves the Component which renders the
     * content for this tab.
     * 
     * @param parentFrame the Frame used by the ace dialog 
     */
    public JComponent getComponent()
    {
        timeDayPanel = new TimeDayPanel();
        timeDayPanel.getAccessibleContext().setAccessibleDescription(i18n("info"));
		p.setPreferredSize(new Dimension(490, 270));
        return p;
    }

    /**
     * Indicates the preferred tab position in the tabbed pane.
     * Range: 0 to 10 or -1 for LAST.
     * If multiple tabs have the same preferred position,
     * the tabs are ordered by name.
     * 
     * @return the preferred tab position in the tabbed pane
     */
    public int getPreferredPosition()
    {
        return TAB_POSITION;
    }
    
    /**
     * Retrieves the title for this tab.
     * The title should be short, usually one word.
     * 
     * @return the title string for this tab.
     */
    public String getTitle()
    {
        return i18n("title");
    }

	/**
	 * Notification that this tab has been selected in the UI
	 */
    public void tabSelected()
    {
		if(isInitialized)
			return;
		isInitialized = true;
		
        p.setBorder(BorderFactory.createEmptyBorder(VERT_WINDOW_INSET,
                HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET));
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel infoLabel = new JLabel();
        infoLabel.setText(i18n("info"));
        gbl.setConstraints(infoLabel, gbc);
        p.add(infoLabel);
        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbl.setConstraints(timeDayPanel, gbc);
        p.add(timeDayPanel);
    }
	
	/**
	 * Called when the Help button is pressed.
	 */
    public void helpInvoked()
	{
		ConsoleHelp.showContextHelp("ace-time");
	}

    /**
     * Called when the OK button is pressed.
     */
    public void okInvoked()
    {
    }

    /**
     * Called when the cancel button is pressed.
     */
    public void cancelInvoked()
    {
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
        int days[] = timeDayPanel.getDaySelection();
        int hours[] = timeDayPanel.getHourSelection();
        
        if(days.length < 7)
        {
            StringBuffer newACI = new StringBuffer();
            newACI.append(" and \n(" + KEYWORD_DAYOFWEEK + " = \"");
            for(int i = 0; i < days.length; i++)
            {
                if(i > 0)
                    newACI.append(",");
                newACI.append(DAYS[days[i]]);
            }
            newACI.append("\")");
        
            if(existingACI.toString().endsWith("\n;)"))
            {
                int len = existingACI.length() - 3;
                existingACI.insert(len, newACI);
            }
        }

        if(hours.length < 24)
        {
            String startTime = "";
            String endTime = "";
            if(hours.length > 0)
            {
                startTime = String.valueOf(hours[0]) + "00";
                endTime = String.valueOf(hours[hours.length-1]+1) + "00";
            }
            StringBuffer newACI = new StringBuffer();
            newACI.append(" and \n(");
            newACI.append(KEYWORD_TIMEOFDAY + " >= ");
            newACI.append("\"" + startTime + "\"");
            newACI.append(" and ");
            newACI.append(KEYWORD_TIMEOFDAY + " < ");
            newACI.append("\"" + endTime +"\"");
            newACI.append(")");
            
            if(existingACI.toString().endsWith("\n;)"))
            {
                int len = existingACI.length() - 3;
                existingACI.insert(len, newACI);
            }
        }

		return existingACI;
        
	}

    
    /**
     * Returns a list of supported ACI attributes (keywords, operators, values).
     * This information is used when editing manually for the purposes of
     * syntax checking, color highlighting, and word completion.
     * 
     * Alphanumeric and digit characters are treated as required literals.
     * Special characters:
     * "|" used to indicate multiple choices
     * "*" used to indicate zero or more characters
     * "#" used to indicate one numeric characters
     */
    public ACIAttribute[] getSupportedAttributes()
    {
        StringBuffer dayList = new StringBuffer();
        for(int i = 0; i < DAYS.length; i++)
        {
            dayList.append(DAYS[i]);
            if(i < DAYS.length-1)
                dayList.append("|");
        }
        
        return new ACIAttribute[] 
            {
                new ACIAttribute(KEYWORD_TIMEOFDAY, "=|!=|>|>=|<|<=", "\"####\""),
                new ACIAttribute(KEYWORD_DAYOFWEEK, "=", "\"" + dayList.toString() + "\""),
            };
    }
}
