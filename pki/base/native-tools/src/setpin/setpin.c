/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */


/* Set-pin tool */


/* This will modify the specified attribute in the directory
   You must add the pin objectclass to the schema
   e.g in config/slapd.oc.conf

   attribute pin bin
   objectclass pinPerson
        superior organizationalPerson
   allows 
        pin
*/

/*
 History:
   version 1.2  - upgraded to NSS 3.3.1
 */

#define SETPIN_VERSION "1.2"

#include "options.h"
#include "setpin_options.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <ldap.h>
#include <ldap_ssl.h>

#define USE_NSS_RANDOM

#ifdef USE_NSS_RANDOM
/* removed #include <secrng.h> as of NSS 3.9 */
/* removed from nss3_3_1 secrngt.h*/
typedef struct RNGContextStr RNGContext;
#endif

#include <sechash.h>

#include <plhash.h>
#include <prerror.h>
#include <ctype.h>

#include <secoidt.h>
#include <nss.h>

extern int equals(char *s, char *t);
extern SECStatus PK11_HashBuf(SECOidTag hashAlg,
                              unsigned char *out,
                              unsigned char *in,
                              int32 len);
extern SECStatus PK11_GenerateRandom(unsigned char *data,
                                     int len);

/* use NSS's new generic hash api */
#define USE_NSS_GEN_HASH

void exitError(char *errstring);
void exitLDAPError(char *errstring);
void doLDAPBind();
void doLDAPSearch(LDAPMessage **result);
void doLDAPUnbind();
void processSearchResults(LDAPMessage *r);
char *newPassword();
void initrandom();
void testpingen();
void do_setup();


char *sha1_pw_enc( char *pwd );

int errcode=0;

LDAP *ld=NULL;
char *programName = NULL;

FILE *output;
FILE *input;


PLHashTable *pinHashTable=NULL;

#ifdef USE_NSS_RANDOM
RNGContext *rngc = NULL;
#endif

/* this tool should really be changed to use NSPR */
#ifdef _WIN32
#define strcasecmp stricmp
#endif

void exitError(char *errstring) {
  char *errbuf;
  
  errbuf = malloc(strlen(errstring)+strlen(programName)+10);

  sprintf(errbuf,"%s error : %s\n",programName,errstring);
  fputs(errbuf,stderr);
  exit(errcode);
}


void exitLDAPError(char *errstring) {
  char *ldaperr;
  char *newerror;
  int err;

  err = ldap_get_lderrno(ld, NULL, NULL);
  ldaperr = ldap_err2string(err);
  newerror = (char*) malloc((errstring?strlen(errstring):0) + (ldaperr?strlen(ldaperr):0) +5);
  sprintf(newerror,"%s (%s)",errstring?errstring:"",ldaperr?ldaperr:"");
  exitError(newerror);
}


/* This returns an allocated string, like strdup does, except that
  the duplicate string begins with the first non-whitespace character */

char * trim_strdup(char *s)
{
  	while (*s == ' ' || *s == '\t') {
		s++;
		}
	
	if (*s == '\0') return NULL;

	return strdup(s);

}

void readInputFile() {
  int more_to_read=1;
  char *thedn, *thepin;
  int linenum=0;

  pinHashTable = PL_NewHashTable(256, 
                                 PL_HashString,
                                 PL_CompareStrings,
                                 PL_CompareValues,
                                 NULL,  /* allocOps */
                                 NULL);
  if (pinHashTable == NULL) {
    errcode=9;
    exitError("Couldn't create dn->pin hashtable");
  }

  if (o_input) {

    do {
      char line[4096];
      char *n;
      char *checkdn;

      
      thedn = NULL;
      thepin = NULL;
      
      do {
        n = fgets(line,4096,input);
		linenum++;
        if (! n) {
          more_to_read = 0;
          break;
        }
        
        /* replace newline with null byte */
        
        line[strlen(line)-1] = 0;
        
        if (! strncmp("dn:",line,3)) {
          thedn = trim_strdup(&line[3]);
		  if (thedn == NULL) {
		  	fprintf(stderr,"warning: empty line not allowed at line: %d\n",linenum);
		  	}
        }
        
        if (! strncmp("pin:",line,4)) {
          thepin = trim_strdup(&line[4]);
        }
        
      } while (strlen(line));
      
      /* first check to see if that dn is already in the hashtable */

      if (thepin == NULL) {
        thepin = strdup("");
      }

      if (thedn && thepin) {

        checkdn = (char*) PL_HashTableLookup(pinHashTable,
                                             thedn);
        if (checkdn) {
          char msg[256];
          errcode = 10;
          strcpy(msg,"Duplicate entry in input file for dn=");
          strcat(msg,thedn);
          exitError(msg);
        }
        
        PL_HashTableAdd(pinHashTable,
                        thedn,
                        thepin);
          fprintf(stderr, "Reading dn/pin ( %s, %s )\n", thedn, thepin);
        if (o_debug) {
          fprintf(stderr, "Reading dn/pin ( %s, %s )\n", thedn, thepin);
        }

      }
	  else {
	  	if (o_debug) {
	  		fprintf(stderr," ...ignoring\n");
			}
		}

    } while (more_to_read);

  }
}
  
  



int main(int ac, char **av) {
  char *error;
  LDAPMessage *search_results;

  programName = av[0];
  if (strlen(av[0]) == 0) {
    strcpy(programName, "setpin");
  }
  else {
    strcpy(programName, av[0]);
  }

  if (ac == 1) {
    int i=0;
      fprintf(stderr,"Setpin utility. Version " SETPIN_VERSION "\n"
	  	"(C) 2005 Fedora Project.\n"
		"Unauthorized distribution prohibited\n\n");
      fprintf(stderr,"To set up directory for pin usage, modify setpin.conf, "
					 "then run:\n   %s optfile=<svr_root>/bin/cert/tools/setpin.conf\n", programName);
      fprintf(stderr,"\nUsage:  %s option=value ... option=value\n\n", programName);

    for (i=0; i< 200; i+=2) {
      if (valid_args[i]) {
        fprintf(stderr,"%13s : %s\n",valid_args[i],valid_args[i+1]);
      }
      else {
        errcode=0;
        fprintf(stderr,"\n");
        exit(errcode);
      }
    }
  }

  error = OPT_parseOptions(ac, av, valid_args);
  if (error) {
    errcode=7;
    exitError(error);
  }

  setDefaultOptions();

  getOptions();
  fprintf(stderr,"\n");
  if (o_debug) {
    fprintf(stderr,"about to validateOptions\n");
  }

  validateOptions();

  /* Initialize random number generator */
  initrandom();

  if (o_debug) {
    fprintf(stderr,"about to doLDAPBind\n");
  }

  if (! o_testpingen) {
  	doLDAPBind();
  }

  if (o_setup) {
	do_setup();
  }

  if (o_output) {
    output = fopen(o_output,"w");
    if (!output) {
      errcode=5;
      exitError("Couldn't open output file");
    }
  }
  else {
    output = stdout;
  }

  if (o_testpingen) {
	testpingen();
 	exit(0);
  }

  if (o_input) {
    input = fopen(o_input,"r");
    if (!input) {
      errcode=8;
      exitError("Couldn't open input file");
    }
  }

  readInputFile();

  if (o_debug) {
    fprintf(stderr,"about to doLDAPSearch\n");
  }

  doLDAPSearch(&search_results);
  
  if (o_debug) {
    fprintf(stderr,"about to processSearchResults\n");
  }
  
  processSearchResults(search_results);
  
  if (output != stdout) {
    fclose(output);
  }

  return 0;
}



/* This function implements the 'setup' procedure, invoked when the user
   specified 'setup' as one of the arguments. The point is that in this
   mode, schema modifications are performed to add these things to the
   directory schema:
    if (schemachange argument is specified)
    - 'pin' attribute as specified by the 'attribute' argument (default 'pin')
    - 'pinPerson' objectclass as specified by the 'objectclass argument (dfl: pinperson)
    if ('pinmanager' argument specified)
    - pin manager user, with permission to remove the pin for the basedn specified

*/

void do_setup() {
  int i;

  char *x_values[]={NULL,NULL,NULL};
  char *a1_values[]={NULL,NULL};
  char *a2_values[]={NULL,NULL};
  char *a3_values[]={NULL,NULL};
  char *a4_values[]={NULL,NULL};
  LDAPMod x,a1,a2,a3,a4;
  LDAPMod *mods[10];
  char* password=NULL;
  int err;

  x_values[0] = malloc(1024);

	doLDAPBind();
	
	if (o_schemachange) {
		
      sprintf(x_values[0],"( %s-oid NAME '%s' DESC 'User Defined Attribute' SYNTAX '1.3.6.1.4.1.1466.115.121.1.5' SINGLE-VALUE )",
			o_attribute,
			o_attribute);

    fprintf(stderr,"Adding attribute: %s\n",x_values[0]);
      x_values[1] = NULL;
      x.mod_op = LDAP_MOD_ADD;
      x.mod_type = "attributetypes";
      x.mod_values = x_values;
      mods[0] = &x;
      mods[1] = NULL;
      
      i = ldap_modify_s(ld, "cn=schema", mods);
	
      if (i != LDAP_SUCCESS) {

  err = ldap_get_lderrno(ld, NULL, NULL);
	  	if (err != LDAP_TYPE_OR_VALUE_EXISTS) {
         	exitLDAPError("couldn't modify schema when creating pin attribute");
	     }
		else fprintf(stderr," .. successful\n\n");
      }

      sprintf(x_values[0],"( %s-oid NAME '%s' DESC 'User Defined ObjectClass' SUP 'top' MUST ( objectclass ) MAY ( aci $ %s )",
		  o_objectclass,o_objectclass,
		  o_attribute);

    fprintf(stderr,"Adding objectclass: %s\n",x_values[0]);

      x_values[1] = NULL;
      x.mod_op = LDAP_MOD_ADD;
      x.mod_type = "objectclasses";
      x.mod_values = x_values;
      mods[0] = &x;
      mods[1] = NULL;

      
      i = ldap_modify_s(ld, "cn=schema", mods);
	
      if (i != LDAP_SUCCESS) {
  		err = ldap_get_lderrno(ld, NULL, NULL);
	  	if (err != LDAP_TYPE_OR_VALUE_EXISTS) {
          exitLDAPError("couldn't modify schema when creating objectclass");
		}
		else fprintf(stderr," .. successful\n\n");
       }
    }

    if (o_pinmanager) {

	  if (o_pinmanagerpwd == NULL) {
    		exitError("missing pinmanagerpwd argument");
	  }
	  if (o_basedn == NULL) {
			exitError("missing basedn argument");
	  }
			
	  password = sha1_pw_enc( o_pinmanagerpwd );
		
      fprintf(stderr,"Adding user: %s\n",o_pinmanager);

      a1_values[0] = "pinmanager";
      a1_values[1] = NULL;
      a1.mod_op = 0;
      a1.mod_type = "sn";
      a1.mod_values = a1_values;

      a2_values[0] = "pinmanager";
      a2_values[1] = NULL;
      a2.mod_op = 0;
      a2.mod_type = "cn";
      a2.mod_values = a2_values;

      a3_values[0] = password;
      a3_values[1] = NULL;
      a3.mod_op = 0;
      a3.mod_type = "userPassword";
      a3.mod_values = a3_values;

      a4_values[0] = "person";
      a4_values[1] = NULL;
      a4.mod_op = 0;
      a4.mod_type = "objectclass";
      a4.mod_values = a4_values;

      mods[0] = &a1;
      mods[1] = &a2;
      mods[2] = &a3;
      mods[3] = &a4;
	  mods[4] = NULL;

	  
      i = ldap_add_s(ld, o_pinmanager, mods);

      if (i != LDAP_SUCCESS) {
  		err = ldap_get_lderrno(ld, NULL, NULL);
	  	if (!( err == LDAP_TYPE_OR_VALUE_EXISTS || err == LDAP_ALREADY_EXISTS)) {
          exitLDAPError("couldn't create new user");
        }
		else fprintf(stderr," .. successful\n\n");
       }


/* modify aci on basedn to allow pinmanager to modify pin attr */
		
      fprintf(stderr,"modifying ACI for: %s\n",o_basedn);

      sprintf(x_values[0],"(target=\"ldap:///%s\")"
					 "(targetattr=\"pin\")"
             		 "(version 3.0; acl \"Pin attribute\"; "
             		  "allow (all) userdn = \"ldap:///%s\"; "
             		  "deny(proxy,selfwrite,compare,add,write,delete,search) "
             		  "userdn = \"ldap:///self\"; ) ",
				o_basedn,
				o_pinmanager);

	  x_values[1] = malloc(1024);

      sprintf(x_values[1],"(target=\"ldap:///%s\")"
					 "(targetattr=\"objectclass\")"
             		 "(version 3.0; acl \"Pin Objectclass\"; "
             		  "allow (all) userdn = \"ldap:///%s\"; "
             		  " ) ",
				o_basedn,
				o_pinmanager);

      x_values[2] = NULL;
      x.mod_op = LDAP_MOD_ADD;
      x.mod_type = "aci";
      x.mod_values = x_values;

      mods[0] = &x;
      mods[1] = NULL;
	  
      i = ldap_modify_s(ld, o_basedn, mods);

      if (i != LDAP_SUCCESS) {
  		err = ldap_get_lderrno(ld, NULL, NULL);
	  	if (!( err == LDAP_TYPE_OR_VALUE_EXISTS || err == LDAP_ALREADY_EXISTS)) {
          exitLDAPError("couldn't modify aci on basedn");
		}
		else fprintf(stderr," .. successful\n\n");
       }
   }
		
exit(0);

}



int ldif_base64_encode(
   unsigned char *src, char *dst, int srclen, int lenused );

/* do password hashing */

/*
 * Number of bytes each hash algorithm produces
 */
#define SHA1_LENGTH     20


char *
sha1_pw_enc( char *pwd )
{
    unsigned char   hash[ SHA1_LENGTH ];
    char        *enc;

    /* SHA1 hash the user's key */
    PK11_HashBuf(SEC_OID_SHA1,hash,pwd,strlen(pwd));
	enc = malloc(256);

    sprintf( enc, "{SHA}");

    (void)ldif_base64_encode( hash, enc + 5,
        SHA1_LENGTH, -1 );

    return( enc );
}




/* check the first 8 characters to see if this is a string */

int isstring(char *s) {
  int i=0;

  for (i=0;i<8;i++) {
    if (*s == 0) return 1;
    if (! isprint(*s)) return 0;
    s++;
  }
  return 1;
}


void doLDAPBind() {
  char errbuf[1024];
  int port=389;
  int r;

  if (o_port == NULL) {
    if (o_ssl) {
      port = 636;
	  /* fprintf(stderr,"o_ssl = %0x, o_certdb = %0x, o_nickname= %0x\n",o_ssl,o_certdb,o_nickname); */
    }
    else {
      port = 389;
    }
  }
  else {
    port = atoi(o_port);
  }

  if (o_debug) {
    fprintf(stderr,"# connecting to %s:%d\n",o_host,port);
  }

  if (o_ssl) {
	printf("SSL not currently supported.\n");
	exit(0);
  	/* ld = ldapssl_init(o_host,port,LDAPSSL_AUTH_CNCHECK); */
  }
  else {
  	ld = ldap_init(o_host,port);
  }
  if (ld == NULL) {
    errcode=4;
    exitError("could not connect to directory server");
  }

  if (o_debug) {
    fprintf(stderr,"# ldap_init completed\n");
  }
    
  r = ldap_simple_bind_s(ld,o_binddn,o_bindpw);
  if (r != LDAP_SUCCESS) {
    sprintf(errbuf,"could not bind to %s:%d as %s",o_host,port,o_binddn);
    if (strstr(o_binddn,"=") == NULL) {
      strcat(errbuf,". Perhaps you missed the 'CN=' part of the bin DN?");
    }
    exitLDAPError(errbuf);
  }

  if (o_debug) {
    fprintf(stderr,"# ldap_simple_bind_s completed\n");
  }

}
  

void doLDAPSearch(LDAPMessage **result ) {
  int r;
  char errbuf[1024];

  r = ldap_search_s( ld, o_basedn, LDAP_SCOPE_SUBTREE,
                     o_filter, NULL, 0, result );

  if (r != LDAP_SUCCESS ) {
    sprintf(errbuf,"could not complete search with that filter. Check filter and basedn");
    exitLDAPError(errbuf);
  }

  if (o_debug) {
    fprintf(stderr,"# ldap_search_s completed\n");
  }

}

void doLDAPUnbind(){
  ldap_unbind(ld);
}


void processSearchResults(LDAPMessage *r) {
  LDAPMessage *e;
  char *dn;
  char *a;
  char **vals;
#ifdef USE_NSS_GEN_HASH
  /* HASHContext *hcx;
  HASH_HashType ht; */
#else
#endif
  int i;
  BerElement *ber;
  char *objectclass_values[]={NULL,NULL};
  int change=0;
  int pin_objectclass_exists=0;
  LDAPMod objectclass, pinattribute;
  LDAPMod *mods[3];
  SECStatus status = SECFailure;

  char *saltval;
  int action;
  char *hashbuf_source = NULL;
  char hashbuf_dest[256];
  char errbuf[1024];
  int pindatasize= 0;
  char *pindata = NULL;
  char *generatedPassword = NULL;
  struct berval *bvals[2];
  struct berval bval;

  bvals[0] = &bval;
  bvals[1] = NULL;

  /* Check whether any results were found. */
  i = ldap_count_entries( ld, r );

  fprintf(stderr,"filter %s found %d matching results.\n", o_filter,i);
  
  /* for each entry print out name + all attrs and values */
  for ( e = ldap_first_entry( ld, r ); e != NULL;
        e = ldap_next_entry( ld, e ) ) {
    
    generatedPassword = NULL;

    if ( (dn = ldap_get_dn( ld, e )) != NULL ) {
      fprintf(stderr, "Processing: %s\n", dn );
      if (o_input) {
        generatedPassword = (char*) PL_HashTableLookup(pinHashTable,dn);
        if (generatedPassword) {
          fprintf(stderr, " found user from input file\n");
        }
        if (! generatedPassword) {
          fprintf(stderr, " Skipping (not in input file)\n");
          continue;
        }
      }
    }


    /* what we do here is go through all the entries looking for
       'objectclass'.
    */

    pin_objectclass_exists = 0;
    change = 0;

#define ACTION_NONE    0
#define ACTION_REPLACE 1
#define ACTION_ADD     2

    action = ACTION_ADD;

    saltval = NULL;
    /* loop through the entries */
    for ( a = ldap_first_attribute( ld, e, &ber );
          a != NULL; a = ldap_next_attribute( ld, e, ber ) ) {

      if ((vals = ldap_get_values( ld, e, a)) != NULL ) {

        if (o_debug && (! strcasecmp(o_debug,"attrs"))) {
          for ( i = 0; vals[i] != NULL; i++ ) {
            char *bin;
            bin = "<binary>";
            if (isstring(vals[i])) {
              bin = vals[i];
            }

            fprintf(stderr, " %s: %s\n",a,bin);
          }
        }

        if (o_debug) {
		fprintf(stderr," examining attribute: %s\n",a);
          	for ( i = 0; vals[i] != NULL; i++ ) {
			fprintf(stderr,"   val[%d]: %s\n",i,vals[i]);
		}
	}

        if (o_saltattribute != NULL) {
          if (!strcasecmp(a,o_saltattribute)) {
            saltval = vals[0];
            if (o_debug) {
              fprintf(stderr," setting salt value to: %s\n",saltval);
            }
          }
        }
	
        if (!strcasecmp(a,"objectclass")) {
          /* check if we have a pin objectclass already */
          /* Cycle through all the values for this 
             entry, looking for the one which matches the 
             objectclass we specified */

          /* if user specified objectclass= on the commandline,
             without any value, then the objectclass is assumed to
             exist already */
          if (strlen(o_objectclass) == 0) {
	    if (o_debug) { fprintf(stderr, " user objectclass assumed to already exist\n"); }
            pin_objectclass_exists=1;
          }
          else {
            for ( i = 0; vals[i] != NULL; i++ ) {
	      if (o_debug) { fprintf(stderr, " checking vals[%d]=%s == objectclass=%s  -> %d \n",
				i,vals[i], o_objectclass, strcasecmp(vals[i],o_objectclass)); }
              if (!strcasecmp(vals[i],o_objectclass)) {
                if (o_debug) {
                  fprintf(stderr, " %s: %s found\n", a, vals[i] );
                }
                pin_objectclass_exists = 1;
              }
            }
          }
        }
        else if (!strcasecmp(a,o_attribute)) {
          if (o_clobber) {
            action = ACTION_REPLACE;
          }
          else {
            action = ACTION_NONE;
          }
        }

        ldap_value_free( vals );
      }
      ldap_memfree( a );
    }

    if (o_debug) { fprintf(stderr, " Did the objectclass exist? %d\n", pin_objectclass_exists); }

    /* add the objectclass attribute if it doesn't already exist */

    if (! pin_objectclass_exists) {
      if (o_debug) {
        fprintf(stderr,"objectclass: %s doesn't exist, adding\n",o_objectclass);
      }
      objectclass_values[0] = o_objectclass;
      objectclass_values[1] = NULL;
      objectclass.mod_op = LDAP_MOD_ADD;
      objectclass.mod_type = "objectclass";
      objectclass.mod_values = objectclass_values;
      mods[0] = &objectclass;
      mods[1] = NULL;
      
      if (o_write) {
        i = ldap_modify_s(ld, dn, mods);
	
        if (i != LDAP_SUCCESS) {
          exitLDAPError("couldn't modify attribute"); 
        }
      }
    }

    pinattribute.mod_type = o_attribute;

    /* password could have been set from input file. If not, set it now */
    if (generatedPassword == NULL || (strlen(generatedPassword) == 0)) {
      generatedPassword = newPassword();
    }

    /* should we hash the password? */
    if (o_hash) {

      /* we hash the DN of the user and the PIN together */

      if (hashbuf_source) {
        free(hashbuf_source);
      }
      if (o_debug) {
	  	fprintf(stderr,"checking salt attribute...\n");
		}
      if (saltval == NULL) {
        if (o_saltattribute != NULL) {
		  errcode = 11;
          exitError("specified salt attribute not found for this user");
        }
      if (o_debug) {
	  	fprintf(stderr,"setting salt attribute to dn...\n");
		}
        saltval = dn;
      }

      hashbuf_source =
        malloc(strlen(saltval) + strlen(generatedPassword) + 10);
      
      strcpy(hashbuf_source,saltval);
      strcat(hashbuf_source,generatedPassword);

      if (o_debug) {
	  	fprintf(stderr,"hashing this: %s\n",hashbuf_source);
		}

      saltval = NULL;

      /* We leave one byte at the beginning of the hash
         buffer, to support the hash type */

#define SENTINEL_SHA1 0
#define SENTINEL_MD5  1
#define SENTINEL_NONE '-' 

      if ((!strcmp(o_hash,"SHA1")) || (!strcmp(o_hash,"sha1")) ) {
        status = PK11_HashBuf(SEC_OID_SHA1,
                              (unsigned char *)hashbuf_dest+1,
                              (unsigned char *)hashbuf_source,
                              strlen(hashbuf_source)
                              );
        hashbuf_dest[0] = SENTINEL_SHA1;
        pindatasize = SHA1_LENGTH + 1;
      }
      else if ((!strcmp(o_hash,"MD5")) || (!strcmp(o_hash,"md5")) ) {
	
        status = PK11_HashBuf(SEC_OID_MD5,
                              (unsigned char *)hashbuf_dest+1,
                              (unsigned char *)hashbuf_source,
                              strlen(hashbuf_source)
                              );
        hashbuf_dest[0] = SENTINEL_MD5;
        pindatasize = MD5_LENGTH + 1;
      }
      else if ((!strcmp(o_hash,"NONE")) || (!strcmp(o_hash,"none")) ) {

	    hashbuf_dest[0] = SENTINEL_NONE;
		status = SECSuccess;
		memcpy(hashbuf_dest+1,
			hashbuf_source,
			strlen(hashbuf_source)
			);
		}
	  else {
	  	sprintf(errbuf,"Unsupported hash type '%s'. Must be one of 'sha1', 'md5' or 'none",o_hash);
		errcode = 7;
		exitError(errbuf);
		}
      
      if (status != SECSuccess) {
        sprintf(errbuf,"Error hashing pin (%d)",PR_GetError());
		errcode = 9;
        exitError(errbuf);
      }
      
      pindata = hashbuf_dest;
    }
    else {
      pindata = generatedPassword;
      pindatasize = strlen(generatedPassword);
    }
    
    bval.bv_len = pindatasize;
    bval.bv_val = pindata;

    fprintf(stderr," Adding new %s\n",o_attribute);

    if (! o_write) {
        fprintf(stderr, " [NOTE: 'write' was not specified, so no changes will be made to the directory]\n");
    }
      
    pinattribute.mod_bvalues = bvals;
    if (action == ACTION_REPLACE) {
      pinattribute.mod_op = LDAP_MOD_REPLACE|LDAP_MOD_BVALUES;
      if (o_debug) {
        fprintf(stderr," %s exists, replacing\n",o_attribute);
      }
    }
    else if (action == ACTION_ADD) {
      if (o_debug) {
        fprintf(stderr," %s doesn't exist, adding\n",o_attribute);
      }
      pinattribute.mod_op = LDAP_MOD_ADD|LDAP_MOD_BVALUES;
    }
    else if (action == ACTION_NONE) {
      if (o_debug) {
        fprintf(stderr," %s exists. not replacing\n",o_attribute);
      }
      goto skip_write;
    }
    mods[0] = &pinattribute;
    mods[1] = NULL;


    if (o_write) {
      i = ldap_modify_s(ld, dn, mods);
      
      if (i != LDAP_SUCCESS) {
        exitLDAPError("couldn't modify attribute");
      }
    }

    
        skip_write:
    
    fprintf(output,"dn:%s\n",dn);
    fprintf(output,"%s:%s\n",o_attribute,generatedPassword);
	if (o_debug) {
		fprintf(stderr,"o_write = %0x\n",(unsigned int)o_write);
		}
    if (! o_write) {
      fprintf(output,"status:notwritten\n");
    }
    else {
      if (action == ACTION_NONE) {
        fprintf(output,"status:notreplaced\n");
        }
      else {
        if (i != LDAP_SUCCESS) {
          fprintf(output,"status:writefailed\n");
        }
        else {
			if (action == ACTION_ADD) {
            fprintf(output,"status:added\n");
            }
            else if (action == ACTION_REPLACE) {
              fprintf(output,"status:replaced\n");
              }
            }
		}
      }

    fprintf(output,"\n");

    if (dn) {
      ldap_memfree( dn );
      dn = NULL;
    }

    if ( ber != NULL ) {
      ber_free( ber, 0 );
    }
    fprintf(stderr, "\n" );
  }
  ldap_msgfree( r );
}


/* this function uses i_minlength and i_maxlength to determine the
   size of the password to generate */

static char *UCalpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


static char *LCalpha = "abcdefghijklmnopqrstuvwxyz";
static char *numbers = "0123456789";
static char *punc = "!#$%&*+,-./:;<=>?@[]^{|}";

static char *charpool = NULL;  /* carpool, geddit? */
static int charpoolsize;

static char *RNG_ALPHA = "RNG-alpha";
static char *RNG_PRINTABLEASCII = "RNG-printableascii";
static char *RNG_ALPHANUM = "RNG-alphanum";


/* build the pool of characters we can use for the password */

void buildCharpool() {
  char err_buf[1024];
  charpool = (char*) malloc(256);

  charpool[0] = '\0';
    
  if ( o_case == NULL) {
    strcat(charpool,LCalpha);       /* then add the lowercase */
  }
  else {
    if (strcmp(o_case,"upperonly")) {
	  errcode = 7;
      exitError("Illegal value for case=");
    }
  }
  
  
  if ( !strcmp(o_gen,RNG_ALPHA) ||
       !strcmp(o_gen,RNG_ALPHANUM) ||
       !strcmp(o_gen,RNG_PRINTABLEASCII) ) {
    strcat(charpool,UCalpha);        /* add uppercase chars */
  }
  else {
    sprintf(err_buf,"invalid value '%s' for gen= option",o_gen);
	errcode = 7;
    exitError(err_buf);
  }
  
  if ( strcmp(o_gen,"RNG-alpha")) { /* not alpha-only */
    strcat(charpool,numbers);
  }
  if (! strcmp(o_gen,"RNG-printableascii")) {  
    strcat(charpool, punc);
  }
  if (o_debug) {
    fprintf(stderr,"Character pool: %s\n",charpool);
  }
  charpoolsize = strlen(charpool);
}
  

/* initialize random number generator */

void initrandom() {
  char err_buf[1024];
#ifdef USE_NSS_RANDOM
  if( NSS_Initialize( "",
                      "",
                      "",
                      "",
                      NSS_INIT_NOCERTDB |
                      NSS_INIT_NOMODDB  |
                      NSS_INIT_FORCEOPEN ) != SECSuccess ) {
    sprintf(err_buf,"Couldn't initialize NSS (error code %d)\n",PR_GetError());
    errcode = 9; 
    exitError(err_buf);
  }
#else
  srand(time(NULL));
#endif

}

  
unsigned short getRandomShort() {
  unsigned short r;
#ifdef USE_NSS_RANDOM
  PK11_GenerateRandom( ( unsigned char * ) &r, sizeof( r ) );
  if (o_debug) {
    /* fprintf(stderr,"Random: %d\n",r); */
  }
  return r;
#else 
  return (unsigned short) rand();
#endif
}


/*
 * this function is important. It needs review.
 * 
 * returns a random number in the range (0 .. max-1)
 */

/* We have a short, rno, and we want to convert this to a number
   in the required range by just using (rno % max). However,
   this may result in some of the numbers at the end of 'rno's
   range being selected more frequently. So, if random number
   select is in this range, we will pick another.
   
   As an example, assume:
     a short is 4 bits (0..15)
     max is 6
     
     0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
     a  a  a  a  a  a  b  b  b  b  b  b  X  X  X  X

     we want to reject everything more than 11

     we take 16 (that largest number which can be in a short+1)
     divide by 'max', which is 6. This gives us 2. Multiply by
     max, gives us 12. Subtract 1, which is 11, our highest
     allowable range. Now we do the modulus.

*/

unsigned short getRandomInRange(unsigned short max) {
  unsigned short rno;
  unsigned short result;

  unsigned short max_allowed_rno =
    ((65536 / max) * max) -1;

  do {
    rno = getRandomShort();
    
  } while (rno >max_allowed_rno);

  result = rno % max;

  assert(result < max);
    
  return result;

}


char * newPassword() {
  static char *pw_buf=NULL;
  unsigned short l;
  unsigned short r;
  int i;

  if (pw_buf == NULL) {
    pw_buf = (char *) malloc(i_maxlength+5);
  }

  if (charpool == NULL) {
    buildCharpool();
  }

  /* decide how long the password should be */
  /* It must be between i_minlength and i_maxlength */

  if (i_minlength == i_maxlength) {
    l = i_minlength;
  }
  else {
    l = getRandomInRange((unsigned short)(1 + i_maxlength - i_minlength));
    l += i_minlength;
  }
  
  for (i=0; i<l; i++) {
    r = getRandomInRange((unsigned short)(charpoolsize));
    pw_buf[i] = charpool[r];
  }
  pw_buf[l] = '\0';

  return pw_buf;

}


void testpingen() {
	int count=25;
	int i,j;
	int pwlen;
	char *pw;
	unsigned int index[256];
	unsigned int *totals;
	char c;

 	if (! equals(o_testpingen,"")) {
		count = atoi(o_testpingen);
	}

  	if (charpool == NULL) {
    	buildCharpool();
  	}

	/* last spot is used to hold invalid chars */
	totals = malloc(sizeof(int)*(charpoolsize+1));
	for (i=0;i<(charpoolsize);i++) {
		totals[i] = 0;
	}
	totals[charpoolsize]=0;
	for (i=0;i<256;i++) {
		index[i] = 255;  /* indicates->invalid */
	}
	for (i=0;i<charpoolsize;i++) {
		index[(int)(charpool[i])] = i;
	}

	for (i=0;i<count;i++) {
		pw = newPassword();
		if (o_debug) {
			fprintf(output,"%d:%s\n",i+1,pw);
		}
		pwlen = strlen(pw);
		for (j=0;j<pwlen;j++) {
			c = pw[j];
			if (index[(int)c] == 255) {
				printf("\ninvalid char found: %02x %c\n",c,c);
				totals[charpoolsize]++;
			}
			else {
				totals[index[(int)c]]++;
			}
		}
		free(pw);
	}

	for (i=0;i<charpoolsize;i++) {
		fprintf(output,"%c: %10d\n",charpool[i],totals[i]);
	}
	fprintf(output,"invalid: %10d\n",totals[charpoolsize]);
		
}
	
  

