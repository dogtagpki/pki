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
#include <string.h>
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "main/NameValueSet.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#ifdef __cplusplus
extern "C"
{
#endif

static PR_CALLBACK void*
_AllocTable(void* pool, PRSize size)
{
    return PR_MALLOC(size);
}

static PR_CALLBACK void
_FreeTable(void* pool, void* item)
{
    PR_DELETE(item);
}

static PR_CALLBACK PLHashEntry*
_AllocEntry(void* pool, const void* key)
{
    return PR_NEW(PLHashEntry);
}

static PR_CALLBACK void
_FreeEntry(void* pool, PLHashEntry* he, PRUintn flag)
{
    if( he == NULL ) {
        return;
    }

    if (flag == HT_FREE_VALUE) {
        if( he->value != NULL ) {
            PL_strfree( ( char* ) he->value );
            he->value = NULL;
        }
    } else if (flag == HT_FREE_ENTRY) {
        if( he->key != NULL ) {
            PL_strfree( ( char* ) he->key );
            he->key = NULL;
        }
        if( he->value != NULL ) {
            PL_strfree( ( char* ) he->value );
            he->value = NULL;
        }
        PR_DELETE(he);
    }
}

static PLHashAllocOps _AllocOps = {
    _AllocTable,
    _FreeTable,
    _AllocEntry,
    _FreeEntry
};

#ifdef __cplusplus
}
#endif

TPS_PUBLIC NameValueSet::NameValueSet()
{ 
	m_set = PL_NewHashTable(3, PL_HashString, 
			PL_CompareStrings, PL_CompareValues, 
			&_AllocOps, NULL);
}

TPS_PUBLIC NameValueSet::~NameValueSet ()
{ 
    if( m_set != NULL ) { 
        PL_HashTableDestroy( m_set );
        m_set = NULL;
    }

    return;
}

/**
 * Parsers string of format "n1=v1&n2=v2..."
 * into a NameValueSet.
 */
TPS_PUBLIC NameValueSet *NameValueSet::Parse(const char *s, const char *separator)
{
	NameValueSet *set = NULL;
	char *pair;
	char *line = NULL;
	int i;
        int len;
	char *lasts = NULL;

	if (s == NULL)
		return NULL;
	set = new NameValueSet();
	line = PL_strdup(s);
	pair = PL_strtok_r(line, separator, &lasts);
	while (pair != NULL) {
                len = strlen(pair);
	        i = 0;
		while (1) {
                        if (i >= len) {
				goto skip;
                        }
			if (pair[i] == '\0') {
				goto skip;
			}
			if (pair[i] == '=') {
				pair[i] = '\0';
				break;
			}
			i++;
		}
                set->Add(&pair[0], &pair[i+1]);
skip:
		pair = PL_strtok_r(NULL, separator, &lasts);
	}
    if( line != NULL ) {
        PL_strfree( line );
        line = NULL;
    }
	return set;
} 

typedef struct {
	int index;
	char *key;
} Criteria;

#ifdef __cplusplus
extern "C"
{
#endif

static PRIntn CountLoop(PLHashEntry *he, PRIntn index, void *arg)
{
        Criteria *criteria = (Criteria *)arg;
	criteria->index++;
        return HT_ENUMERATE_NEXT;
}

static PRIntn Loop(PLHashEntry *he, PRIntn index, void *arg)
{
    Criteria *criteria = (Criteria *)arg;
    if (criteria != NULL && index == criteria->index) {
	    criteria->key = (char *)he->key;
            return HT_ENUMERATE_STOP;
    } else {
            return HT_ENUMERATE_NEXT;
    }
}

#ifdef __cplusplus
}
#endif

TPS_PUBLIC int NameValueSet::Size()
{
        Criteria criteria;
	criteria.index = 0;
	criteria.key = NULL;
	PL_HashTableEnumerateEntries(m_set, &CountLoop, &criteria);
	return criteria.index;
}

TPS_PUBLIC char *NameValueSet::GetNameAt(int pos)
{
        Criteria criteria;
	criteria.index = pos;
	criteria.key = NULL;
	PL_HashTableEnumerateEntries(m_set, &Loop, &criteria);
	return criteria.key;
}

/**
 * Checks if a key is defined. 
 */
TPS_PUBLIC int NameValueSet::IsNameDefined(const char *name)
{ 
	if (GetValue(name) == NULL) 
		return 0; 
	else 
		return 1;
}

TPS_PUBLIC void NameValueSet::Add(const char *name, const char *value)
{
	if (IsNameDefined(name)) {
	  PL_HashTableAdd(m_set, PL_strdup(name), PL_strdup(value));
	} else {
	  PL_HashTableAdd(m_set, PL_strdup(name), PL_strdup(value));
	}
}

TPS_PUBLIC void NameValueSet::Remove(const char *name)
{
	if (IsNameDefined(name)) {
	  PL_HashTableRemove(m_set, name);
    }
}

TPS_PUBLIC char *NameValueSet::GetValue(const char *name)
{ 
	return (char *)PL_HashTableLookupConst(m_set, name);
}

/**
 * Retrieves configuration value as integer.
 */
TPS_PUBLIC int NameValueSet::GetValueAsInt(const char *name)
{
        char *value = NULL;

        value = (char *)GetValue(name);
        if (value == NULL)
          return 0;
        return atoi(value);
}

/**
 * Retrieves configuration value as integer. If name is
 * not defined, default value is returned.
 */
TPS_PUBLIC int NameValueSet::GetValueAsInt(const char *name, int def)
{
        char *value = NULL;

        value = (char *)GetValue(name);
        if (value == NULL)
          return def;
        return atoi(value);
}


/**
 * Retrieves configuration value as boolean.
 */
TPS_PUBLIC int NameValueSet::GetValueAsBool(const char *name)
{
        char *value = NULL;

        value = (char *)GetValue(name);
        if (value == NULL)
          return 0;
        if (PL_CompareStrings("true", value) != 0)
          return 1;
        else
          return 0;
}

/**
 * Retrieves configuration value as boolean. If name is
 * not defined, default value is returned.
 */
TPS_PUBLIC int NameValueSet::GetValueAsBool(const char *name, int def)
{
        char *value = NULL;

        value = (char *)GetValue(name);
        if (value == NULL)
                return def;
        if (PL_CompareStrings("true", value) != 0)
          return 1;
        else
          return 0;
}

/**
 * Retrieves configuration value as string. If key is
 * not defined, default value is returned.
 */
TPS_PUBLIC char *NameValueSet::GetValueAsString(const char *name, char *def)
{
        char *value = NULL;

        value = (char *)GetValue(name);
        if (value == NULL)
                return def;
        return value;
}

/**
 * Retrieves configuration value as string.
 */
TPS_PUBLIC char *NameValueSet::GetValueAsString(const char *name)
{
        return (char *)GetValue(name);
}

