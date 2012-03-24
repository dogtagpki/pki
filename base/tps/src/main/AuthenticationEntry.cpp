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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plstr.h"
#include "main/AuthenticationEntry.h"

/**
 * Constructs a base authentication
 */
AuthenticationEntry::AuthenticationEntry ()
{
    m_lib = NULL;
    m_Id = NULL;
    m_type = NULL; 
    m_authentication = NULL;
}

/**
 * Destructs processor.
 */
AuthenticationEntry::~AuthenticationEntry ()
{
    if (m_lib != NULL) {
        PR_UnloadLibrary(m_lib);
        m_lib = NULL; 
    }

    if( m_Id != NULL ) {
        PL_strfree( m_Id ); 
        m_Id = NULL; 
    }

    if( m_type != NULL ) {
        PL_strfree( m_type ); 
        m_type = NULL; 
    }

    m_authentication = NULL;
}

void AuthenticationEntry::SetLibrary(PRLibrary* lib) {
    m_lib = lib;
}

PRLibrary *AuthenticationEntry::GetLibrary() {
    return m_lib;
}

void AuthenticationEntry::SetId(const char *id) {
    m_Id = PL_strdup(id);
}

char *AuthenticationEntry::GetId() {
    return m_Id;
}

void AuthenticationEntry::SetAuthentication(Authentication *auth) {
    m_authentication = auth;
}

Authentication *AuthenticationEntry::GetAuthentication() {
    return m_authentication;
}

void AuthenticationEntry::SetType(const char *type) {
    m_type = PL_strdup(type);
}

char *AuthenticationEntry::GetType() {
    return m_type;
}
