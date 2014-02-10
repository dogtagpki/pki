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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.rest;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.dogtagpki.server.rest.ACLInterceptor;
import org.dogtagpki.server.rest.AccountService;
import org.dogtagpki.server.rest.AuditService;
import org.dogtagpki.server.rest.AuthMethodInterceptor;
import org.dogtagpki.server.rest.GroupService;
import org.dogtagpki.server.rest.MessageFormatInterceptor;
import org.dogtagpki.server.rest.SelfTestService;
import org.dogtagpki.server.rest.SystemCertService;
import org.dogtagpki.server.rest.SystemConfigService;
import org.dogtagpki.server.rest.UserService;
import org.dogtagpki.server.tps.config.ConfigService;

import com.netscape.certsrv.base.PKIException;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSApplication extends Application {

    private Set<Object> singletons = new LinkedHashSet<Object>();
    private Set<Class<?>> classes = new LinkedHashSet<Class<?>>();

    public TPSApplication() {

        // account
        classes.add(AccountService.class);

        // audit
        classes.add(AuditService.class);

        // installer
        classes.add(SystemConfigService.class);

        // user and group management
        classes.add(GroupService.class);
        classes.add(UserService.class);

        // system certs
        classes.add(SystemCertService.class);

        // activities
        classes.add(ActivityService.class);

        // authenticators
        classes.add(AuthenticatorService.class);

        // certificates
        classes.add(TPSCertService.class);

        // config
        classes.add(ConfigService.class);

        // connections
        classes.add(ConnectionService.class);

        // profiles
        classes.add(ProfileService.class);
        classes.add(ProfileMappingService.class);

        // selftests
        classes.add(SelfTestService.class);

        // tokens
        classes.add(TokenService.class);

        // exception mapper
        classes.add(PKIException.Mapper.class);

        // interceptors
        singletons.add(new AuthMethodInterceptor());
        singletons.add(new ACLInterceptor());
        singletons.add(new MessageFormatInterceptor());
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }

}
