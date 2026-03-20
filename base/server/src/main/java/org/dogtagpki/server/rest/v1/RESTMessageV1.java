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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.rest.v1;

import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.base.RESTMessage;

public class RESTMessageV1 extends RESTMessage {

    public RESTMessageV1(MultivaluedMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry : form.entrySet()) {
            attributes.put(entry.getKey(), entry.getValue().get(0));
        }
    }
}
