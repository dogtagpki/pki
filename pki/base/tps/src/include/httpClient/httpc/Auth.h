/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifndef __PS_AUTH_H__
#define __PS_AUTH_H__

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "ldap.h"

class PSConfig;
class Pool;
class PoolNode;

/**
 * Utility classes for authentication and authorization
 *
 * @author  rweltman@netscape.com
 * @version 1.0
 */

/**
 * Maintains a pool of LDAP connections; not yet implemented as a pool
 */
class LDAPConnectionPool {
public:
	LDAPConnectionPool( const char *host, int port, int poolSize );
	virtual ~LDAPConnectionPool() {}
    int Initialize();
    PoolNode *GetConnection();
    PoolNode *GetAuthenticatedConnection( const char *binddn,
                                          const char *bindpwd );
    void ReleaseConnection( PoolNode *node );
protected:
private:
    const char* m_host;
    int m_port;
    int m_size;
    Pool *m_pool;
    bool m_initialized;
};

/**
 * Produces an authenticator for an auth domain and authenticates
 */
class EXPORT_DECL Authenticator {
public:
	virtual int Authenticate( const char *username,
                              const char *password,
                              char *&actualID ) = 0;
	static Authenticator *GetAuthenticator( const char *domain );
};

class EXPORT_DECL LDAPAuthenticator:public Authenticator {
public:
	LDAPAuthenticator();
	virtual ~LDAPAuthenticator();
	virtual int Authenticate( const char *username,
                              const char *password,
                              char *&dn );

protected:
    static int GetHashSize();
	char *CheckCache( const char *username,
                      const char *password );
	void UpdateCache( const char *username,
                      const char *dn,
                      const char *password );
    char *CreateHash( const char *password,
                      char *hash,
                      int maxChars );
    /**
     * Returns the DN corresponding to a username, if any
     *
     * @param username The user name to look up
     * @param status The status of an LDAP search, if any
     * @return The corresponding DN, or NULL if no DN found
     */
    char *GetUserDN( const char *username, int& status );

private:
    LDAPConnectionPool *m_pool;
    const char* m_host;
    int m_port;
    const char* m_binddn;
    const char* m_bindpassword;
    const char* m_basedn;
    const char* m_searchfilter;
    const char* m_searchscope;
    int   m_nsearchscope;
    char* m_attrs[2];
    StringKeyCache *m_cache;
};

class EXPORT_DECL LDAPAuthorizer {
public:
	LDAPAuthorizer();
	virtual ~LDAPAuthorizer();
	static LDAPAuthorizer *GetAuthorizer();
	virtual int Authorize( const char *dn,
                           const char *pwd,
                           const char *methodName );

protected:
	int GetLdapConnection( LDAP** ld );
	int CheckCache( const char *username,
                    const char *methodName );
	void UpdateCache( const char *username,
                      const char *methodName );

private:
    LDAPConnectionPool *m_pool;
    const char* m_binddn;
    const char* m_bindpassword;
    const char* m_basedn;
    const char* m_searchfilter;
    const char* m_searchscope;
    int   m_nsearchscope;
    char* m_attrs[2];
    StringKeyCache *m_cache;
};

#endif // __PS_HELPER_H__
