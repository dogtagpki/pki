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
package com.netscape.cms.servlet.common;

import java.util.Locale;

import com.netscape.certsrv.authority.IAuthority;

/**
 * This interface represents a template filler.
 *
 * @version $Revision$, $Date$
 */
public interface ICMSTemplateFiller {
    // common template variables.
    public final static String ERROR = "errorDetails";
    public final static String ERROR_DESCR = "errorDescription";
    public final static String EXCEPTION = "unexpectedError";

    public static final String HOST = "host";
    public static final String PORT = "port";
    public static final String SCHEME = "scheme";

    public static final String AUTHORITY = "authorityName";

    public static final String REQUEST_STATUS = "requestStatus";

    public static final String KEYREC_ID = "keyrecId";
    public static final String REQUEST_ID = "requestId";

    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority mAuthority, Locale locale, Exception e)
            throws Exception;
}
