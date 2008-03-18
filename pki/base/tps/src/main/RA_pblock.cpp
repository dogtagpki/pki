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

#ifdef __cplusplus
extern "C"
{
#endif

#include "prmem.h"

#ifdef __cplusplus
}
#endif

#include <string.h>
#include "engine/RA.h"
#include "main/Buffer.h"
#include "main/Memory.h"
#include "main/Util.h"
#include "main/RA_pblock.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

TPS_PUBLIC RA_pblock::RA_pblock( int tm_nargs, Buffer_nv** tm_nvs )
{
    m_nargs = tm_nargs;

    if( tm_nvs != NULL ) {
        for( int i = 0; i < MAX_NVS; i++ ) {
            m_nvs[i] = tm_nvs[i];
        }
    } else {
        for( int i = 0; i < MAX_NVS; i++ ) {
            m_nvs[i] = NULL;
        }
    }
}

TPS_PUBLIC RA_pblock::~RA_pblock()
{
    free_pblock();
}

Buffer_nv **RA_pblock::GetNVs()
{
    return m_nvs;
}

// returns url-decoded value
TPS_PUBLIC Buffer *RA_pblock::find_val( const char * name )
{
    for( int i = 0; i < m_nargs; i++ ) {
        if( i >= MAX_NVS ) {
          continue;
        }

        if( ( m_nvs[i] == NULL )       ||
            ( m_nvs[i]->name == NULL ) ||
            ( m_nvs[i]->value == NULL ) ) {
            continue;
        }

        if( PR_CompareStrings( m_nvs[i]->name, name ) == 1 ) {
            return m_nvs[i]->value;
        }
    }

    return NULL;
}

TPS_PUBLIC char *RA_pblock::get_name( int i )
{
    return m_nvs[i]->name; 
}

TPS_PUBLIC int RA_pblock::get_num_of_names()
{
    return m_nargs;
}

// returns non-urldecoded value
TPS_PUBLIC char* RA_pblock::find_val_s( const char * name )
{
    RA::Debug( LL_PER_PDU, "RA_pblock::find_val_s",
               "searching for name= %s", name );

    int end = m_nargs;

    if( MAX_NVS < m_nargs ) {
        RA::Error( "RA_pblock::find_val_s",
                   "MAX_NVS too small, needs increasing... "
                   "m_nargs= %d, MAX_NVS=%d", m_nargs, MAX_NVS );
        end = MAX_NVS;
    }

    for( int i = 0; i < end; i++ ) {
        if( ( m_nvs[i] == NULL )       ||
            ( m_nvs[i]->name == NULL ) ||
            ( m_nvs[i]->value_s == NULL ) ) {
            continue;
        }

        /* RA::Debug( LL_PER_PDU, "RA_pblock::find_val_s", */
        /*            "found %s", m_nvs[i]->name );        */

        if( PR_CompareStrings( m_nvs[i]->name, name ) == 1 ) {
            return m_nvs[i]->value_s;
        }
    }

    return NULL;
}

void RA_pblock::free_pblock()
{
    RA::Debug( LL_PER_PDU, "RA_pblock::free_pblock", "in free_pblock" );

    int end = m_nargs;

    if( MAX_NVS < m_nargs ) {
        RA::Error( "RA_pblock::free_pblock",
                   "MAX_NVS too small, needs increasing... "
                   "m_nargs= %d, MAX_NVS=%d", m_nargs, MAX_NVS );
        end = MAX_NVS;
    }

    for( int i = 0; i < end ; i++ ) {
        if( m_nvs[i] == NULL ) {
            continue;
        }

        if( m_nvs[i]->value ) {
            delete( m_nvs[i]->value );
            m_nvs[i]->value = NULL;
        }

        if( m_nvs[i]->value_s ) {
            delete( m_nvs[i]->value_s );
            m_nvs[i]->value_s = NULL;
        }

        if( m_nvs[i]->name != NULL ) {
            PL_strfree( m_nvs[i]->name );
            m_nvs[i]->name = NULL;
        }

        if( m_nvs[i] != NULL ) {
            PR_Free( m_nvs[i] );
            m_nvs[i] = NULL;
        }
    }

    RA::Debug( LL_PER_PDU, "RA_pblock::free_pblock", "in free_pblock done" );
}

