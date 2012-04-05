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
package com.netscape.cms.servlet.request;

import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;

/**
 * An interface representing a request parser which
 * converts Java request object into name value
 * pairs and vice versa.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IReqParser {

    /**
     * Maps request object into argument block.
     */
    public void fillRequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException;
}
