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
// (C) 2020 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.Repository;

@WebServlet(
        name = "caUpdateNumberRange",
        urlPatterns = "/admin/ca/updateNumberRange",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="ID",            value="caUpdateNumberRange"),
                @WebInitParam(name="interface",     value="admin"),
                @WebInitParam(name="AuthMgr",       value="TokenAuth"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="resourceID",    value="certServer.clone.configuration.UpdateNumberRange"),
        }
)
public class CAUpdateNumberRange extends UpdateNumberRange {

    @Override
    public Repository getRepository(String type) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();

        if (type.equals("request")) {
            return engine.getCertRequestRepository();

        } else if (type.equals("serialNo")) {
            return engine.getCertificateRepository();

        } else if (type.equals("replicaId")) {
            return engine.getReplicaIDRepository();
        }

        throw new EBaseException("Unsupported repository: " + type);
    }
}
