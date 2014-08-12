// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include "plstr.h"
#include "main/Base.h"
#include "main/Login.h"
#include "main/Memory.h"

/**
 * Constructs a login object.
 */
Login::Login (char *uid, char *pwd)
{
    if (uid == NULL) {
	    m_uid = NULL;
    } else {
	    m_uid = PL_strdup(uid);
    }
    if (pwd == NULL) {
	    m_pwd = NULL;
    } else {
	    m_pwd = PL_strdup(pwd);
    }
}

/**
 * Destructs login object.
 */
Login::~Login ()
{
    if( m_uid != NULL ) {
        PL_strfree( m_uid );
        m_uid = NULL;
    }
    if( m_pwd != NULL ) {
        PL_strfree( m_pwd );
        m_pwd = NULL;
    }
}

/**
 * Retrieves user id.
 */
char *Login::GetUID()
{
	return m_uid;
}

/**
 * Retrieves password.
 */
char *Login::GetPassword()
{
	return m_pwd;
}
