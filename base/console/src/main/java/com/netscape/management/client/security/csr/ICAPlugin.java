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
package com.netscape.management.client.security.csr;

import java.util.*;

/**
* Interface for extending Console's Certificate Request, Renew, and Install wizards.
* 
* In addition to implementing this API, the JAR file must package a manifest
* file containing the following properties (listed as name/value pairs):
* 
* Name - description TBD
* User URL - description TBD
* Update URL - description TBD
* Description - description TBD
* Icon - description TBD
* 
* TODO: improve Javadocs, see: http://java.sun.com/products/jdk/javadoc/writingdoccomments.html
* TODO: implement sample plugin
*/
public interface ICAPlugin
{
    /**
     * Status code indicating than an error has occurred.
     */
    public static int STATUS_ERROR = 0;
    
    /**
     * Status code indicating that the CSR has been accepted by the CA
     * for further processing.  A Certificate may be issued later.
     */
    public static int STATUS_QUEUED = 1;

    /**
     * Status code indicating that the CA has issued a Certificate.
     */
    public static int STATUS_ISSUED = 2;

    /**
     * Initialization code indicating that this plugin is being
     * asked to request a new certificate.
     */
    public static int INIT_REQUEST = 1;
    
    /**
     * Initialization code indicating that this plugin is being
     * asked to renew an existing certificate.
     */
    public static int INIT_RENEW = 2;
    
    /**
     * Initialization code indicating that this plugin is being
     * asked to replace an existing certificate.
     */
    public static int INIT_REPLACE = 3;
    
    /**
     * Initialization code indicating that this plugin is being
     * asked to install a certificate that has been requested.
     */
    public static int INIT_INSTALL = 4;
    
    /**
     * A constant indicating that the "user information"
     * page sequence is to be returned by getPageSequence(int)
     */
    public static int UI_BEGINING_SEQUENCE = 1;
    
    /**
     * A constant indicating that the "status information"
     * page sequence is to be returned by getPageSequence(int)
     */
    public static int UI_ENDING_SEQUENCE = 2;
    
    /**
     * Informs the plugin that it has been selected by the user, 
     * and why it is being called.  It also provides an object
     * that provides miscellaneous utility functions.
     * This is the first method called after instantiation.
     *
     * @param     constant INIT_RENEW, INIT_REPLACE, or INIT_INSTALL
     * @param     ICAPluginUtil object indicating
     */
    public void initialize(int INIT_CODE, ICAPluginUtil util);
    
    /**
     * Returns certificate information entered by user.
     * This information is encrypted by Console into a
     * PKCS #10 (CSR) blob, which is then returned to this
     * plugin for submission to the CA.
     * 
     * @see http://www.rsasecurity.com/rsalabs/pkcs/pkcs-10/index.html 
     * @see submitCSR(String)
     * @return    string containing certificate information formatted as a DN
     */
    public String getCertificateDN();

    /**
     * Submits the Certificate Signing Request to the CA.  
     * This method is called after Console has encoded the 
     * Certificate DN into a PKCS #10 blob.    The CA may 
     * issue the certificate immediately or queue the request
     * for further processing.  The return value indicates  
     * how the request has been handled: 
     * STATUS_QUEUED if the pending request has not been processed
     * STATUS_ISSUED if the certificate has been issued
     * STATUS_ERROR in case of an error
     * 
     * @see      STATUS constants for details
     * @see      getCertificateDN()
     * @param    csr    PKCS #10 (CSR) blob
     * @return   STATUS_QUEUED, STATUS_ISSUED, or STATUS_ERROR
     */
    public int submitCSR(String csr);

     /**
     * Inquires with the CA if a pending request has been processed.
     * 
     * The return value is one of the following status codes:
     * STATUS_QUEUED if the pending request has not been processed
     * STATUS_ISSUED if the certificate has been issued
     * STATUS_ERROR in case of an error
     * 
     * @see STATUS constants for details
     * @return STATUS_QUEUED, STATUS_ERROR, or STATUS_ISSUED
     */
    public int checkPendingRequest();

    /**
     * Retrieves the certificate data.
     * The data should be encoded as a String in PKCS #7 format.
     * See: http://www.rsasecurity.com/rsalabs/pkcs/pkcs-7/index.html 
     * 
     * @return    String containing certificate data
     */
    public String getCertificateData(); 

    /**
     * Returns the first UI page in a particular sequence.
     * The sequence is indicated by uiConstant. 
     * 
     * @param     constant UI_BEGINING_SEQUENCE or UI_ENDING_SEQUENCE
     * @return    IUIPage object that defines page content
     */
    public IUIPage getUIPageSequence(int uiConstant);
    
    /**
     * Retrieves property data internal to this plugin.
     * Console saves this data persistently, then returns it to the 
     * plugin (across instantiations) to recover the previous state.
     * 
     * An example of when this method might be called is when the CA cannot
     * cannot issue a Certificate immediately and returns a STATUS_PENDING
     * return code from submitCSR().  At a later time, this session will need 
     * to be recovered to check the state of the pending request.
     * 
     * @return String value for the given property name
     */
    public String getProperty(String name);
    
    /**
     * Stores a property name and value for this plugin.
     * 
     * @param name    String name of property
     * @param value   String value of property
     * @see getProperty(String)
     */
    public void setProperty(String name, String value);
    
    /**
     * Retrieves a list of property names currently stored in this plugin. 
     * 
     * @see getProperty(String)
     * @return Enumeration of property names.
     */
    public Enumeration getPropertyNames();
} 
