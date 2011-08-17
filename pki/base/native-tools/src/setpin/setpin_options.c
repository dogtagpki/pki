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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

extern int OPT_getValue(char *option, char **output);
extern void exitError(char *errstring);
extern int errcode;

#define PW_DEFAULT_LENGTH 6

char *valid_args[] = {
  "host",     "LDAP host                                [required]",
  "port",     "LDAP port (default 389)",
  "binddn",   "DN to bind to directory as               [required]",
  "bindpw",   "Password associated with above DN ",
  "filter",   "Ldap search filter e.g. filter=(uid=*)   [required]",
/*   "ssl",      "Use SSL LDAP connection?", */
/*  "certdb",   "Path to SSL Client certificate database directory (not yet implemented)", 
  "nickname", "Nickname of cert to use for SSL client auth (not yet implemented)",
  */
  "basedn",   "Base DN used for LDAP search",
  "length",   "Length of generated pins (default 6)",
  "minlength","Minimum length of generated pins (not to be used with 'length')",
  "maxlength","Maximum length of generated pins (not to be used with 'length')",
  "gen",      "Permitted chars for pin. Type 'setpin gen' for more info",
  "case",     "Restrict case of pins 'case=upperonly'",
  "objectclass", "Objectclass of LDAP entry to operate on    (default pinPerson)",
  "attribute","Which LDAP attribute to write to           (default pin)",
  "hash",     "Hash algorithm used to store pin: 'none', 'md5' or 'sha1' (default)",
  "saltattribute", "Which attribute to use for salt            (default: dn)",
  "input",    "File to use for restricting DN's, or providing your own pins",
  "output",   "Redirect stdout to a file",
  "write",    "Turn on writing to directory (otherwise, pins will not get written)",
  "clobber",  "Overwrite old pins in the directory",
  "testpingen",  "Test pin generation mode. testpingen=count",
  "debug",    "Turn on debugging, or use debug=attrs for even more",
  "optfile",  "Read in options (one per line) from specified file",
  "setup",    "Switch to setup mode",
  "pinmanager","Pin Manager user to create in setup mode",
  "pinmanagerpwd","password of pin manager user in setup mode",
  "schemachange","make schema changes in setup mode",
  NULL
};

int valid_args_len = sizeof(valid_args)/sizeof(char *);

int i_length, i_minlength, i_maxlength;

char *attribute=NULL;

char *o_certdb,*o_nickname,*o_binddn,*o_bindpw,*o_filter,*o_ssl,
  *o_basedn,*o_input,*o_host,*o_port,*o_length,*o_minlength,*o_hash,
  *o_maxlength,*o_gen,*o_case,*o_attribute,*o_objectclass,*o_output,
  *o_retry,*o_debug, *o_write, *o_clobber, *o_saltattribute, *o_testpingen,
  *o_setup,*o_pinmanager,*o_pinmanagerpwd,*o_schemachange;

void setDefaultOptions() {
 o_certdb=   ".";
 o_nickname= NULL; 
 o_binddn=   NULL;
 o_bindpw=   NULL;
 o_filter=   NULL;
 o_ssl=      NULL;
 o_basedn=   NULL;
 o_input=   NULL;
 o_host=     NULL;
 o_port=     NULL;
 o_length=   NULL;   /* default set later */
 o_minlength=NULL;
 o_maxlength=NULL;
 o_gen=      "RNG-alphanum";
 o_case=     NULL;
 o_attribute="pin";
 o_hash=     "sha1";
 o_objectclass="pinPerson";
 o_output=   NULL;
 o_retry=    "5";
 o_debug=    NULL;
 o_write=    NULL;
 o_clobber=  NULL;
 o_saltattribute = NULL;
 o_testpingen = NULL;
 o_setup=    NULL;
 o_pinmanager= NULL;
 o_pinmanagerpwd= NULL;
 o_schemachange= NULL;
}

void getOptions() {
  int i;
  char *c;

  i_length = 0;
  i_minlength =0;
  i_maxlength =0;

  OPT_getValue("certdb",   &o_certdb);
  OPT_getValue("nickname", &o_nickname);
  OPT_getValue("binddn",   &o_binddn);
  OPT_getValue("bindpw",   &o_bindpw);
  OPT_getValue("filter",   &o_filter);
  i = OPT_getValue("ssl",      &o_ssl);
  if (i)   o_ssl = "yes";
  OPT_getValue("basedn",   &o_basedn);
  OPT_getValue("input",    &o_input);
  OPT_getValue("host",     &o_host);
  OPT_getValue("port",     &o_port);
  OPT_getValue("length",   &o_length);
  if (o_length) i_length = atoi(o_length);
  OPT_getValue("minlength",&o_minlength);
  if (o_minlength) i_minlength = atoi(o_minlength);
  OPT_getValue("maxlength",&o_maxlength);
  if (o_maxlength) i_maxlength = atoi(o_maxlength);
  OPT_getValue("gen",      &o_gen);
  OPT_getValue("case",     &o_case);
  OPT_getValue("attribute",&o_attribute);
  OPT_getValue("hash",     &o_hash);
  if (o_hash) {
     c = o_hash;
	 while (*c) {
		if (isupper(*c)) {
	    	*c = *c - 'A' + 'a';
		}
		c++;
		}
     }
     
  OPT_getValue("objectclass",&o_objectclass);
  OPT_getValue("output",   &o_output);
  OPT_getValue("retry",    &o_retry);
  i = OPT_getValue("debug",    &o_debug);
  if (i) {
    if (! o_debug) { 
      o_debug = "yes";
    } 
  }
  i = OPT_getValue("write",    &o_write);
  if (i)   o_write = "yes";
  i = OPT_getValue("clobber",    &o_clobber);
  if (i) o_clobber = "yes";
  OPT_getValue("saltattribute",    &o_saltattribute);
  i = OPT_getValue("testpingen",    &o_testpingen);
  if (i) {
	if (!o_testpingen) {
		o_testpingen = "25";
	}
  }
  OPT_getValue("setup",   &o_setup);
  OPT_getValue("pinmanager",   &o_pinmanager);
  OPT_getValue("pinmanagerpwd",   &o_pinmanagerpwd);
  OPT_getValue("schemachange",   &o_schemachange);
  

}

int equals(char *s, char *t) {
  return !(strcmp(s,t));
}

void validateOptions() {
  char *errbuf;

  errbuf = (char *)malloc(2048);
  if (errbuf == NULL) {
    errcode=13;
    exitError("Couldn't allocate 'errbuf'.");
  }

  if (o_nickname  && equals(o_ssl,"no")) {
    sprintf(errbuf,"specifying nickname doesn't make sense with no SSL");
    goto loser;
  }

  if (o_gen == NULL || !
       ( equals(o_gen,"RNG-printableascii") ||
	 equals(o_gen,"RNG-alpha") ||
	 equals(o_gen,"RNG-alphanum") ||
	 equals(o_gen,"FIPS181-printable"))
      ) {
  	printf("Permissible values for gen:\n"
           "   RNG-alpha               : alpha-only characters\n"
           "   RNG-alphanum            : alphanumeric characters\n"
           "   RNG-printableascii      : alphanumeric and punctuation\n");
    if (o_gen) {
		printf("You specified: gen=%s\n",o_gen);
		}
    exit(0);
  }

  if (o_length && (o_minlength || o_maxlength)) {
    strcpy(errbuf,"cannot use minlength or maxlength with length option");
    goto loser;
  }

  if (o_minlength && !o_maxlength) {
    strcpy(errbuf,"if you set minlength, you must also set maxlength");
    goto loser;
  }

  if (!o_minlength && o_maxlength) {
    strcpy(errbuf,"if you set maxlength, you must also set minlength");
    goto loser;
  }

  if (i_minlength > i_maxlength) {
    strcpy(errbuf,"cannot set minlength to be more than maxlength");
    goto loser;
  }

  if (i_length > 0) {
    i_minlength = i_length;
    i_maxlength = i_length;
  }
  else {
    if (i_minlength == 0 && i_maxlength == 0) {
      i_minlength = PW_DEFAULT_LENGTH;
      i_maxlength = PW_DEFAULT_LENGTH;
    }
  }

  if (o_testpingen) {
	free(errbuf);
	return;
  }
  
  if (!o_host || equals(o_host,"")) {
    strcpy(errbuf,"host missing");
    goto loser;
  }

  if (!o_binddn || equals(o_binddn,"")) {
    strcpy(errbuf,"binddn missing");
    goto loser;
  }

  if (!o_bindpw || equals(o_bindpw,"")) {
    strcpy(errbuf,"bindpw missing");
    goto loser;
  }

  if (o_setup != NULL) {
	free(errbuf);
	return;
  }

  if (!o_basedn) {
    fprintf(stderr,"WARNING: basedn not set. Will search from root.\n");
  }

  if (!o_filter || equals(o_filter,""))  {
    strcpy(errbuf,"filter missing. Example filters:\n filter=(uid=*)  - all users with a UID attribute\n filter=(&(uid=*)(ou=Managers))  - all users with a UID and members of the managers group\n");
    goto loser;
  }

  if (!
      (equals(o_hash,"sha1") ||
       equals(o_hash,"md5") ||
       equals(o_hash,"none"))
      ) {
    sprintf(errbuf,"invalid hash: %s",o_hash);
    goto loser;
  }
  if (equals(o_hash,"none")) o_hash = NULL;
  free(errbuf);
      
  return ;
  
 loser:
  errcode=14;
  free(errbuf);
  exitError(errbuf);

}


