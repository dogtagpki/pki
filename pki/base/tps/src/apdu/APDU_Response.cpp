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
#include "apdu/APDU_Response.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a response object.
 */
APDU_Response::APDU_Response ()
{
}

TPS_PUBLIC APDU_Response::APDU_Response (Buffer &data)
{
    m_data = data;
}

/**
 * Destroys a response object.
 */
APDU_Response::~APDU_Response ()
{
}

/**
 * Copy constructor.
 */
APDU_Response::APDU_Response (const APDU_Response &cpy)
{   
    *this = cpy;
}

/**
 * Operator for simple assignment.
 */
APDU_Response& APDU_Response::operator=(const APDU_Response &cpy)
{   
    if (this == &cpy)
      return *this;
    m_data = cpy.m_data;
    return *this;
}



/**
 * Retrieves the byte encoding of the response
 * object including the last 2 state bytes.
 */
TPS_PUBLIC Buffer &APDU_Response::GetData()
{
    return m_data;
}

/**
 * Retrieves the 1st status byte.
 */
BYTE APDU_Response::GetSW1()
{
    if (m_data == NULL) {
        return 0x0;
    } else {
	if (m_data.size() < 2) {
            return 0x0;
        } else {
            return ((BYTE*)m_data)[((int)m_data.size())-2];
	}
    }
}


/**
 * Retrieves the 2nd status byte.
 */
BYTE APDU_Response::GetSW2()
{
    if (m_data == NULL) {
        return 0x0;
    } else {
	if (m_data.size() < 2) {
            return 0x0;
	} else {
            return ((BYTE*)m_data)[((int)m_data.size())-1];
	}
    }
}
