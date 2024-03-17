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


public class DefaultPlugin implements ICAPlugin {

    Hashtable sessionData = new Hashtable();
    public DefaultPlugin() {
    }

    public void initialize(int INIT_CODE, ICAPluginUtil su) {
    }

    public String getCertificateDN() {
	String dn = "";

	if (sessionData.containsKey("dn")) {
	    dn = (String)(sessionData.get("dn"));
	}

	return dn;
    }

    public int submitCSR(String csr) {
	sessionData.put("pkcs#10", csr);
	return STATUS_QUEUED;
    }

    public int checkPendingRequest() {
	return STATUS_QUEUED;
    }

    public String getCertificateData() {
	return "";
    }


    CertRequestInfoPage certReqInfoPage = null;
    CertRequestSubmissionPage certReqSubmitionPage = null;
    public IUIPage getUIPageSequence(int pageType) {
	IUIPage contentPage = null;
	if (pageType == UI_BEGINING_SEQUENCE) {
	    contentPage = (certReqInfoPage == null)?(new CertRequestInfoPage(sessionData)):
                                                    certReqInfoPage;
	} else if (pageType == UI_ENDING_SEQUENCE) {
	    contentPage = (certReqSubmitionPage == null)?(new CertRequestSubmissionPage(sessionData)):
		                                         certReqSubmitionPage;
	}
	return contentPage;
    }

    public String getProperty(String name) {
	return sessionData.get(name).toString();
    }

    public void setProperty(String name, String value) {
	sessionData.put(name, value);
    }

    public Enumeration getPropertyNames() {
	return sessionData.keys();
	/*return new Enumeration() {
	    public boolean hasMoreElements() {
		return false;
	    }
	    public Object nextElement()  {
		throw new NoSuchElementException();
	    }
	};*/
    }
}
