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
package com.netscape.certsrv.notification;

import java.util.Hashtable;
import java.util.Vector;

/**
 * formulates the final email. Escape character '\' is understood.
 * '$' is used preceeding a token name. A token name should not be a
 * substring of any other token name
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IEmailFormProcessor {

    // list of token names
    public final static String TOKEN_ID = "InstanceID";
    public final static String TOKEN_SERIAL_NUM = "SerialNumber";
    public final static String TOKEN_HEX_SERIAL_NUM = "HexSerialNumber";
    public final static String TOKEN_REQUEST_ID = "RequestId";
    public final static String TOKEN_HTTP_HOST = "HttpHost";
    public final static String TOKEN_HTTP_PORT = "HttpPort";
    public final static String TOKEN_ISSUER_DN = "IssuerDN";
    public final static String TOKEN_SUBJECT_DN = "SubjectDN";
    public final static String TOKEN_REQUESTOR_EMAIL = "RequestorEmail";
    public final static String TOKEN_CERT_TYPE = "CertType";
    public final static String TOKEN_REQUEST_TYPE = "RequestType";
    public final static String TOKEN_STATUS = "Status";
    public final static String TOKEN_NOT_AFTER = "NotAfter";
    public final static String TOKEN_NOT_BEFORE = "NotBefore";
    public final static String TOKEN_SENDER_EMAIL = "SenderEmail";
    public final static String TOKEN_RECIPIENT_EMAIL = "RecipientEmail";
    public final static String TOKEN_SUMMARY_ITEM_LIST = "SummaryItemList";
    public final static String TOKEN_SUMMARY_TOTAL_NUM = "SummaryTotalNum";
    public final static String TOKEN_SUMMARY_SUCCESS_NUM = "SummaryTotalSuccess";
    public final static String TOKEN_SUMMARY_FAILURE_NUM = "SummaryTotalFailure";
    public final static String TOKEN_EXECUTION_TIME = "ExecutionTime";

    public final static String TOKEN_REVOCATION_DATE = "RevocationDate";

    /*
     * takes the form template, parse and replace all $tokens with the
     *		 right values.  It handles escape character '\'
     * @param form The locale specific form template,
     * @param tok2vals a hashtable containing one to one mapping
     *	 from $tokens used by the admins in the form template to the real
     *	 values corresponding to the $tokens
     * @return mail content
     */
    public String getEmailContent(String form,
            Hashtable<String, Object> tok2vals);

    /**
     * takes a vector of strings and concatenate them
     */
    public String formContent(Vector<String> vec);

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg);
}
