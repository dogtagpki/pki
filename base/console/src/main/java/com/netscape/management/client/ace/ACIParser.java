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

import java.util.*;

/**
 * A utility class primarily to parse ACI strings 
 * into <name><operator><value> triplets.  
 * This class is used internally by ACIEditor and ACIManager.
 */
class ACIParser
{
    /**
     * Scans an aci String, breaks it up into ACIAttributes
     * which are <name><operator><value> triplets.
     * 
     * @return Vector of ACIAttributes
     */
    public static Vector getACIAttributes(String aci)
    {
        int startIndex = 0;
        Vector aciAttributes = new Vector();
        int length = aci.length();
        for(int i = 0; i < length; i++)
        {
            switch(aci.charAt(i))
            {
                case ' ':  // skip over space
                case '\n': // skip over CR
                    break;
                    
                case '(':
                  i++;
                  // intentional drop through to default
                default:
                  i = parseACIName(aci, i, aciAttributes, startIndex);
                  startIndex = i;
                  break;
            }
            if(i < 0)
            {
                i = -i;
                System.err.println("ACI ERROR: cannot parse at index " + i);
                System.err.println(aci);
                for(int x = 0; x < i; x++)
                    System.err.print(" ");
                System.err.println("^");
                break; // for loop
            }
        }
        return aciAttributes;
    }

    private static int parseACIName(String aci, int i, Vector aciAttributes, int startIndex)
    {
        int length = aci.length();
        StringBuffer name = new StringBuffer();
        // <i> should be pointing to NAME
        // where <aci> is of the form: NAME<OPERATOR>VALUE
        
        boolean isNameFound = false;
        for(; i < length; i++)
        {
            char x = aci.charAt(i);
            switch(x)
            {
                case '\n': // skip over CR
                    break;
                    
                case '(': // skip over leading paren
                case ' ': // skip over leading space
                  if(name.length() > 0)
                    isNameFound = true;
                  break; 
                  
                case '|':  // operators
                case '<':
                case '>':
                case '!':
                case '=':
                    isNameFound = true;
                  break;
                  
                case ')':
                  return i;
                  
                case ';':
                  break;
                  
                default:
                  name.append(x);
                  break;
            }
            
            if(isNameFound)
            {
                if(name.length() > 0)
                {
                    String nameString = name.toString();
                    if(nameString.equalsIgnoreCase("and") || nameString.equalsIgnoreCase("or"))
                    {
                        ACIAttribute aciAttr = new ACIAttribute("", nameString, "", startIndex, i);
                        aciAttributes.addElement(aciAttr);
                        startIndex = i+1;
                    }
                    else
                    {
                        if(aci.charAt(i) == ' ' || aci.charAt(i) == '(')
                            i++;
                        i = parseACIValue(aci, i, nameString, aciAttributes, startIndex);
                        startIndex = i;
                    }
                    if(i > 0) // no error, continue with next NAME/VALUE pair
                    {
                        isNameFound = false;
                        name = null;
                        name = new StringBuffer();
                        i--;
                        continue; // for loop
                    }
                }
                return i; // error, should be negative
            }
        }
        return i;
    }
    
    private static int parseACIValue(String aci, int i, String name, Vector aciAttributes, int startIndex)
    {
        int length = aci.length();
        StringBuffer value = new StringBuffer();
        StringBuffer operator = new StringBuffer();
        // <i> should be pointing to OPERATOR
        // where <aci> is of the form: NAME<OPERATOR>VALUE
        
        boolean isValueFound = false;
        boolean isQuoteOpen = false;
        int countParenthesis = 0;
        for(; i < length; i++)
        {
            char x = aci.charAt(i);
            switch(x)
            {
                case '\n': // skip over CR
                    break;
                    
                case '|': //
                case '<': //
                case '>': // skip over operators
                case '!': //
                case '=': //
                  if(value.length() > 0)
                    value.append(x);
                  else
                    operator.append(x);
                  break;
                
                case ' ': // skip over leading space
                  if(value.length() > 0)
                    value.append(x);
                  break;
                  
                case '"':
                  value.append(x);
                  isQuoteOpen = !isQuoteOpen;
                  if(isQuoteOpen == false)
                  {
                    isValueFound = true;
                  }
                  break; 

                case '(':
                    if(isQuoteOpen == false)
                    {
                        countParenthesis++;
                    }
                    value.append(x);
                    break;
                  
                case ')':
                  if((countParenthesis > 0) || (isQuoteOpen == true))
                  {
                    value.append(x);
                  }
                  if(isQuoteOpen == false)
                  {
                    countParenthesis--;
                    if(countParenthesis <= 0)
                    {
                        isValueFound = true;
                    }
                  }
                  break;
                  
                case ';':
                    isValueFound = true;
                  break;
                  
                default:
                  value.append(x);
                  break;
            }
            
            if(isValueFound)
            {
                int len = value.length(); 
                if(len > 0)
                {
                    String v = value.toString();
                    if(v.endsWith("\""))
                       v = v.substring(0, v.length()-1);
                    
                    
                    if(v.startsWith("\""))
                       v = v.substring(1);
                    
                    ACIAttribute aciAttr = new ACIAttribute(name, operator.toString(), v, startIndex, i);
                    
                    aciAttributes.addElement(aciAttr);
                    return i+1;
                }
                break; // exit for loop, error
            }
        }
        return -i; // error
    }

    public static void main(String[] args)
    {
        //String testaci = "(targetattr=\"*\")(version 3.0; acl \"Enable Group Expansion\"; allow (read, search, compare) groupdnattr=\"ldap:///o=NetscapeRoot?uniquemember?sub\";)";
        //String testaci = "(targetattr=\"*\")(ERROR=)(version 3.0; acl \"Enable Group Expansion\"; allow (read, search, compare) groupdnattr=\"ldap:///o=NetscapeRoot?uniquemember?sub\";)";
        //String testaci = "(targetattr=\"*\")(targetfilter=(|(objectClass=nsManagedDomain)(|(objectClass=nsManagedOrgUnit)(|(objectClass=nsManagedDept)(|(objectClass=nsManagedMailList)(objectClass=nsManagedPerson))))))(version 3.0; acl \"SA domain access\"; allow (all) groupdn=\"ldap:///cn=Service Administrators, o=NDA Spock 1222\";)";
        //String testaci = "(targetattr!=\"uid||ou||owner||nsDAModifiableBy||nsDACapability||mail||mailAlternateAddress||nsDAMemberOf||nsDADomain\")(targetfilter=(objectClass=nsManagedPerson))(version 3.0; acl \"User self modification\"; allow (write) userdn=\"ldap:///self\";)";
        //String testaci = "(target=\"ldap:///cn=postmaster, o=NDA Spock 1222\")(targetattr=\"*\")(version 3.0; acl \"Anonymous access to Postmaster entry\"; allow (read,search) userdn=\"ldap:///anyone\";)";
        //String testaci = "(targetattr=\"*\")(targetfilter=(objectClass=nsManagedDept))(version 3.0; acl \"Dept Adm dept access\"; allow (read,search) userdn=\"ldap:///o=NDA Spock 1222??sub?(nsDAMemberOf=cn=Department Administrators*)\" and groupdnattr=\"ldap:///o=NDA Spock 1222?nsDAModifiableBy\";)";
        //String testaci = "(targetattr!=\"uid||ou||owner||nsDAModifiableBy||nsDACapability||mail||mailAlternateAddress||nsDAMemberOf||nsDADomain\")(targetfilter=(objectClass=nsManagedPerson))(version 3.0; acl \"User self modification\"; allow (write) (userdn=\"ldap:///self\" or userdn=\"ldap:///self\") ;)";
        //String testaci = "(targetattr!=\"*\")(version 3.0; acl \"aclname\"; allow (all) (userdn=\"ldap:///self\" or userdn=\"ldap:///self\") ;)";
        String testaci = "(targetattr = \"*\") (version 3.0; acl \"<Unnamed ACI>\"; allow (all) (userdn = \"ldap:///anyone\") and (dns=\"*.mcom.com\");)";
        
        System.out.println("aci: " + testaci);
        Vector aciData = ACIParser.getACIAttributes(testaci);
        Enumeration e = aciData.elements();
        while(e.hasMoreElements())
        {
            System.out.println((ACIAttribute)e.nextElement());
        }
        
        //System.out.println("\nThe name of this ACI is " + ACIParser.getValue("acl", aciData));
        int index = aciData.indexOf(new ACIAttribute("acl"));
        if(index != -1)
            System.out.println("\nThe name of this ACI is '"+((ACIAttribute)aciData.elementAt(index)).getValue()+"'");
    }
}
