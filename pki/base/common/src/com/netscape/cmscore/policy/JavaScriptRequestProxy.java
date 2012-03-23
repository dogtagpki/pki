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
package com.netscape.cmscore.policy;

import com.netscape.certsrv.policy.IPolicyRule;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;

/**
 *
 * @deprecated
 *
 */
public class JavaScriptRequestProxy {
    IRequest req;

    public JavaScriptRequestProxy(IRequest r) {
        req = r;
    }

    public String getHTTP(String param) {
        return req.getExtDataInString(IRequest.HTTP_PARAMS, param);
    }

    public String get(String param) {
        return req.getExtDataInString(param);
    }

    public PolicyResult applyPolicy(IPolicyRule r) {
        return r.apply(req);
    }

}
