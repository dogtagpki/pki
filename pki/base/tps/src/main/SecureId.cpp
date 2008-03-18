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
#include "main/SecureId.h"
#include "main/Memory.h"

/**
 * Creates a Secure ID object.
 */
SecureId::SecureId (char *value, char *pin)
{
    if (value == NULL) {
	    m_value = NULL;
    } else {
	    m_value = PL_strdup(value);
    }
    if (pin == NULL) {
	    m_pin = NULL;
    } else {
	    m_pin = PL_strdup(pin);
    }
}

/**
 * Destructs a Secure ID object.
 */
SecureId::~SecureId ()
{
    if( m_value != NULL ) {
        PL_strfree( m_value );
        m_value = NULL;
    }
    if( m_pin != NULL ) {
        PL_strfree( m_pin );
        m_pin = NULL;
    }
}

/**
 * Retrieves the optional Secure ID value.
 */
char *SecureId::GetValue()
{
	return m_value;
}

/**
 * Retrieves the Secure ID PIN.
 */ 
char *SecureId::GetPIN()
{
	return m_pin;
}
