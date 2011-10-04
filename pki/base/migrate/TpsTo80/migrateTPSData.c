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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SOLARIS
#include <mozldap6/ldif.h>
#else
#include <mozldap/ldif.h>
#endif
#include <ctype.h>
#include <nspr4/nspr.h>
#include <nspr4/plstr.h>
#include <nspr4/plhash.h>
#include <nspr4/prmem.h>
#include <nspr4/prprf.h>
#include <nspr4/prsystem.h>
#include <errno.h>
#include <string.h>

#define SHORT_LEN 512
#define NO_TOKEN_TYPE "no_token_type"

static PLHashTable *token_set;
static FILE *infile;
static FILE *outfile;

/* hash functions */
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

/* utility functions */
#ifdef SOLARIS
void do_free(char * buf)
{
    if (buf != NULL) {
        PR_Free(buf);
        buf = NULL;
    }
}
#else
inline void do_free(char * buf)
{
    if (buf != NULL) {
        PR_Free(buf);
        buf = NULL;
    }
}
#endif



char *get_field( char *s, char* fname, int len)
{
    char *end = NULL;
    int  n;

    if( ( s = PL_strstr( s, fname ) ) == NULL ) {
        return NULL;
    }

    s += strlen(fname);
    end = PL_strchr( s, ' ' );

    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }

    if (n == 0) {
        return NULL;
    } else if (n > len) {
        /* string too long */
        return NULL;
    } else {
        return PL_strndup( s, n );
    }
}

/*
 * Read the ldif, munge the entry and write to output.
 */
int read_and_modify_ldif() {
    // user changes
    static char agent_entry[] = "dn: cn=TUS Agents,ou=Groups";
    static int agent_ent_len = sizeof(agent_entry)-1;
    static char admin_entry[] = "dn: cn=TUS Adminstrators,ou=Groups";
    static int admin_ent_len = sizeof(admin_entry)-1;
    static char operator_entry[] = "dn: cn=TUS Officers,ou=Groups";
    static int operator_ent_len = sizeof(operator_entry)-1;
    static char user_entry[] = "ou=People";

    // token changes
    static char token_entry[] = "ou=Tokens";

    // activity changes
    static char activity_entry[] = "ou=Activities";

    char *entry = 0;
    int lineno = 0;

    while ((entry = ldif_get_entry(infile, &lineno))) {
        char *begin = entry;

        if (!PL_strncasecmp(entry, agent_entry, agent_ent_len)) {
            process_agent_entry(entry);
        } else if (!PL_strncasecmp(entry, admin_entry, admin_ent_len)) {
            process_admin_entry(entry);
        } else if (!PL_strncasecmp(entry, operator_entry, operator_ent_len)) {
            process_operator_entry(entry);
        } else if (PL_strstr(entry, token_entry) != NULL) {
            process_token_entry(entry);
        } else if (PL_strstr(entry, activity_entry) != NULL) {
            process_activity_entry(entry);
        } else if ((PL_strstr(entry, user_entry) != NULL) && 
                   (PL_strstr(entry, "objectClass: organizationalunit") == NULL))  {
            process_user_entry(entry);
        } else {
            process_unchanged_entry(entry);
            fprintf(outfile, "\n");
        }
        free(begin);
    }
    return 0;
}

/**
 * read the file, parse the activity records
 * record the tokenTypes found for later use
 */
int parse_ldif_activities() {
    // activity changes
    static char activity_entry[] = "ou=Activities";

    char *entry = 0;
    int lineno = 0;

    while ((entry = ldif_get_entry(infile, &lineno))) {
        char *begin = entry;
        if (PL_strstr(entry, activity_entry) != NULL) {
            parse_activity_entry(entry);
        }
        free(begin);
    }
    return 0;
}

int parse_activity_entry(char* entry) {
    static char tokenMsg_attr[] = "tokenMsg";
    static char tokenid_attr[] = "tokenID";
    char *line = entry;
    char *tokenType = NULL;
    char *cuid = NULL;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s\n", entry);
        } else {
            if (!PL_strncasecmp(type, tokenMsg_attr, SHORT_LEN)) {
                tokenType = get_field(value, "tokenType=",SHORT_LEN);
            } else if (!PL_strncasecmp(type, tokenid_attr, SHORT_LEN)) {
                cuid = PL_strdup(value);
            }
        }
    }

    if ((tokenType != NULL) && (cuid != NULL)) {
        if ((char *) PL_HashTableLookupConst(token_set, cuid) == NULL) {
            PL_HashTableAdd(token_set, PL_strdup(cuid), PL_strdup(tokenType));
            //printf("Adding entry: %s %s to hash\n", cuid, tokenType); 
        }
    }
    do_free(cuid);
    do_free(tokenType);
    return 0;
}



/* change uniqueMember -> member */
int process_agent_entry(char* entry) {
    static char member_attr[] = "uniqueMember";

    char *line = entry;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s\n", entry);
        } else {
            if (!PL_strncasecmp(type, member_attr, SHORT_LEN)) {
		fprintf(outfile, "member: %s\n", value);
            } else if ((!PL_strncasecmp(type, "objectClass", SHORT_LEN)) && (!PL_strncasecmp(value, "groupOfUniqueNames", SHORT_LEN))) {
                fprintf(outfile, "objectClass: groupOfNames\n");
            } else {
                fprintf(outfile, "%s", ldif_type_and_value(type, value, vlen));
            }
        }
    } 
    fprintf(outfile, "\n");
    return 0;
}

/* same as agent */
int process_operator_entry(char* entry) {
    return process_agent_entry(entry);
}

/* change uniqueMember -> member 
 * change typo in dn
 */
int process_admin_entry(char* entry) {
    static char member_attr[] = "uniqueMember";
    static char dn_attr[] = "dn";

    char *line = entry;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s", entry);
        } else {
            if (!PL_strncasecmp(type, member_attr, SHORT_LEN)) {
                fprintf(outfile, "member: %s\n", value);
            } else if (!PL_strncasecmp(type, dn_attr, SHORT_LEN)) {
                int rep_size = PL_strlen("cn=TUS Adminstrators,ou=Groups,");
                fprintf(outfile, "dn: cn=TUS Administrators,ou=Groups,%s\n", value + rep_size);
            } else if ((!PL_strncasecmp(type, "objectClass", SHORT_LEN)) && (!PL_strncasecmp(value, "groupOfUniqueNames", SHORT_LEN))) {
                fprintf(outfile, "objectClass: groupOfNames\n");
            } else {
                fprintf(outfile, "%s", ldif_type_and_value(type, value, vlen));
            }
        }
    }
    fprintf(outfile, "\n");
    return 0;
}

int process_user_entry(char *entry) {
    process_unchanged_entry(entry);
    fprintf(outfile, "objectClass: tpsProfileId\n");
    fprintf(outfile, "profileID: All Profiles\n");
    fprintf(outfile, "\n");
    return 0;
}
    
int process_unchanged_entry(char *entry) {
    char *line = entry;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s\n", entry);
        } else {
            fprintf(outfile, "%s", ldif_type_and_value(type, value, vlen));
        }
    }
    return 0;
}

int process_activity_entry(char *entry) {
    static char tokenmsg_attr[] = "tokenMsg";
    static char tokenid_attr[] = "tokenID";
    char *line = entry;
    char *tokenType = NULL;
    char *cuid = NULL;
    char *dn = NULL;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s\n", entry);
        } else {
            fprintf(outfile, "%s", ldif_type_and_value(type, value, vlen));
            
            if (!PL_strncasecmp(type, tokenmsg_attr, SHORT_LEN)) {
                tokenType = get_field(value, "tokenType=",SHORT_LEN);
                if (tokenType != NULL) {
                    fprintf(outfile, "tokenType: %s\n", tokenType);
                }
            } else if (!PL_strncasecmp(type, tokenid_attr, SHORT_LEN)) {
                cuid = PL_strdup(value);
            } else if (!PL_strncasecmp(type, tokenid_attr, SHORT_LEN)) {
                dn = PL_strdup(value);
            }
        }
    }

    if ((tokenType == NULL) && (cuid!= NULL)) {
        // check hash for a value
        if (PL_HashTableLookupConst(token_set, cuid) != NULL) {
            fprintf(outfile, "tokenType: %s\n", (char *) PL_HashTableLookupConst(token_set, cuid));
        } else {
            fprintf(outfile, "tokenType: %s\n", NO_TOKEN_TYPE);
            // log error here - unable to set token type using dn
        }
    }
    fprintf(outfile, "\n");
    do_free(cuid);
    do_free(dn);
    do_free(tokenType);
    
    return 0;
}

int process_token_entry(char* entry) {
    static char cn_attr[] = "cn";
    static char dn_attr[] = "dn";
    char *line = entry;
    char *tokenType = NULL;
    char *dn = NULL;
    while ((line = ldif_getline(&entry))) {
        char *type, *value;
        int vlen = 0;
        int rc;

        if ( *line == '\n' || *line == '\0' ) {
            break;
        }

        /* this call modifies line */
        rc = ldif_parse_line(line, &type, &value, &vlen);
        if (rc != 0) {
            printf("Unknown error processing ldif entry: %s\n", entry);
        } else {
            fprintf(outfile, "%s", ldif_type_and_value(type, value, vlen));

            if (!PL_strncasecmp(type, cn_attr, SHORT_LEN)) {
                if (value != NULL) {
                    tokenType = (char *) PL_HashTableLookupConst(token_set, value);
                }
                if (tokenType != NULL) {
                    fprintf(outfile, "tokenType: %s\n", tokenType);
                } else {
                    fprintf(outfile, "tokenType: %s\n", NO_TOKEN_TYPE);
                }
            } else if (!PL_strncasecmp(type, dn_attr, SHORT_LEN)) {
                dn = PL_strdup(value);
            }
        }
    } 
    if ((tokenType == NULL) && (dn != NULL)) {
        //log the error
    }
    fprintf(outfile, "\n");
    do_free(dn);
    return 0;
}


int main (int argc, char *argv[]) {
   char *in_fname = NULL;
   char *out_fname = NULL;

    if (argc < 3) {
        printf ("Usage:\n  %s infile outfile\n", argv[0]);
        return 1;
    }

    in_fname = argv[1];
    infile = fopen(in_fname, "r");
    if (infile == NULL) {
        perror("Error opening input file");
        return 1;
    }
    
    out_fname = argv[2];
    outfile = fopen(out_fname, "w");
    if (outfile == NULL) {
        perror("Error opening output file");
        return 1;
    }

    //declare hash
    token_set = PL_NewHashTable(3, PL_HashString,
        PL_CompareStrings, PL_CompareValues,
        &_AllocOps, NULL);

   printf("Parsing LDIF file for Token Activities\n");
   parse_ldif_activities();
   rewind(infile);

   printf("Parsing old LDIF file, and creating new LDIF file\n\n");
   read_and_modify_ldif();

   printf("Operation is complete.\nA new LDIF file has been written at %s, \n", out_fname);
   printf("to be imported into the database of your new TPS. \nPlease attend to any errors reported.\n\n");

   fclose(infile);
   fclose(outfile);
   return 0;
}

