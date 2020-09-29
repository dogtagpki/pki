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

#include <pistool.h>


static char *progName;


/*  tkstool commands  */
enum {
    cmd_DeleteKey = 0,
    cmd_PrintHelp,
    cmd_InputGenTransportKey,
    cmd_DisplayKCV,
    cmd_ListKeys,
    cmd_GenMasterKey,
    cmd_NewDBs,
    cmd_ChangePassword,
    cmd_RenameKey,
    cmd_ListSecModules,
    cmd_GenTransportKey,
    cmd_UnWrapMasterKey,
    cmd_Version,
    cmd_WrapMasterKey
};


/*  tkstool options */
enum {
    opt_DBDir = 0,
    opt_PasswordFile,
    opt_TokenName,
    opt_InFile,
    opt_Keyname,
    opt_OutFile,
    opt_DBPrefix,
    opt_NewKeyname,
    opt_TransportKeyname,
    opt_RW,
    opt_NoiseFile,
	opt_NonExportable,
    opt_KeyAlg,
    opt_KeyLength
};


static secuCommandFlag tkstool_commands[] = {
    { /* cmd_DeleteKey            */  'D', PR_FALSE, 0, PR_FALSE },
    { /* cmd_PrintHelp            */  'H', PR_FALSE, 0, PR_FALSE },
    { /* cmd_InputGenTransportKey */  'I', PR_FALSE, 0, PR_FALSE },
    { /* cmd_DisplayKCV           */  'K', PR_FALSE, 0, PR_FALSE },
    { /* cmd_ListKeys             */  'L', PR_FALSE, 0, PR_FALSE },
    { /* cmd_GenMasterKey         */  'M', PR_FALSE, 0, PR_FALSE },
    { /* cmd_NewDBs               */  'N', PR_FALSE, 0, PR_FALSE },
    { /* cmd_ChangePassword       */  'P', PR_FALSE, 0, PR_FALSE },
    { /* cmd_RenameKey            */  'R', PR_FALSE, 0, PR_FALSE },
    { /* cmd_ListSecModules       */  'S', PR_FALSE, 0, PR_FALSE },
    { /* cmd_GenTransportKey      */  'T', PR_FALSE, 0, PR_FALSE },
    { /* cmd_UnWrapMasterKey      */  'U', PR_FALSE, 0, PR_FALSE },
    { /* cmd_Version              */  'V', PR_FALSE, 0, PR_FALSE },
    { /* cmd_WrapMasterKey        */  'W', PR_FALSE, 0, PR_FALSE }
};


static secuCommandFlag tkstool_options[] = {
    { /* opt_DBDir               */  'd', PR_TRUE,  0, PR_FALSE },
    { /* opt_PasswordFile        */  'f', PR_TRUE,  0, PR_FALSE },
    { /* opt_TokenName           */  'h', PR_TRUE,  0, PR_FALSE },
    { /* opt_InFile              */  'i', PR_TRUE,  0, PR_FALSE },
    { /* opt_Keyname             */  'n', PR_TRUE,  0, PR_FALSE },
    { /* opt_OutFile             */  'o', PR_TRUE,  0, PR_FALSE },
    { /* opt_DBPrefix            */  'p', PR_TRUE,  0, PR_FALSE },
    { /* opt_NewKeyname          */  'r', PR_TRUE,  0, PR_FALSE },
    { /* opt_TransportKeyname    */  't', PR_TRUE,  0, PR_FALSE },
    { /* opt_RW                  */  'x', PR_FALSE, 0, PR_FALSE },
    { /* opt_NoiseFile           */  'z', PR_TRUE,  0, PR_FALSE },
    { /* opt_NonExportable		 */  's', PR_FALSE, 0, PR_FALSE },
    { /* opt_KeyAlg              */  'a', PR_TRUE,  0, PR_FALSE },
    { /* opt_KeyLength           */  'l', PR_TRUE,  0, PR_FALSE },
};


int 
main( int argc, char **argv )
{
    CK_KEY_DERIVATION_STRING_DATA  secondDerivationData        = { NULL,
                                                                   0 };
    CK_KEY_DERIVATION_STRING_DATA  thirdDerivationData         = { NULL,
                                                                   0 };
    PK11SlotInfo                  *internalSlot                = NULL;
    PK11SlotInfo                  *slot                        = NULL;
    PK11SymKey                    *symmetricKey                = NULL;
    PK11SymKey                    *masterKey                   = NULL;
    PK11SymKey                    *temporaryMasterKey          = NULL;
    PK11SymKey                    *firstSymmetricKey           = NULL;
    PK11SymKey                    *secondSymmetricKey          = NULL;
    PK11SymKey                    *thirdSymmetricKey           = NULL;
    PK11SymKey                    *transportKey                = NULL;
    PRBool                         readOnly                    = PR_FALSE;
    PRIntn                         KCVLen                      = KCV_LENGTH;
    PRUint8                       *KCV                         = NULL;
    SECItem                        firstSessionKeyShare        = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECItem                        secondSessionKeyShare       = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECItem                        thirdSessionKeyShare        = { siBuffer,
                                                                   NULL,
                                                                   0 };
#if defined(PAD_DES2_KEY_LENGTH)
    SECItem                        paddedFirstSessionKeyShare  = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECItem                        paddedSecondSessionKeyShare = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECItem                        paddedThirdSessionKeyShare  = { siBuffer,
                                                                   NULL,
                                                                   0 };
#endif
    SECItem                        hexInternalKeyKCV           = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECItem                        wrappedMasterKey            = { siBuffer,
                                                                   NULL,
                                                                   0 };
    SECStatus                      rvKCV                       = SECFailure;
    SECStatus                      rvParse                     = SECSuccess;
    SECStatus                      rvNSSinit                   = SECSuccess;
    SECStatus                      rvFindSymKey                = SECSuccess;
    SECStatus                      rvSeedRNG                   = SECSuccess;
    SECStatus                      rvFirstSessionKeyShare      = SECFailure;
    SECStatus                      rvSecondSessionKeyShare     = SECFailure;
    SECStatus                      rvThirdSessionKeyShare      = SECFailure;
    SECStatus                      rvSaveWrappedMasterKey      = SECSuccess;
    SECStatus                      rvSymmetricKeyname          = SECSuccess;
    SECStatus                      rvWrappedMasterKey          = SECSuccess;
    SECStatus                      rvMasterKeyname             = SECSuccess;
    SECStatus                      rv                          = SECSuccess;
    SECStatus                      status                      = PR_FALSE;
    char                           commandToRun                = '\0';
    char                          *DBDir                       = NULL;
    char                          *DBPrefix                    = "";
    char                          *input                       = NULL;
    char                          *keyname                     = NULL;
    char                          *new_keyname                 = NULL;
    char                          *output                      = NULL;
    char                          *SeedNoise                   = NULL;
    char                          *slotname                    = "internal";
    char                          *transport_keyname           = NULL;
    int                            keyAlg                      = 0;
    unsigned int                   keyLength                   = 0;
    int                            commandsEntered             = 0;
    int                            i                           = 0;
    int                            optionsEntered              = 0;
    secuPWData                     pwdata                      = { PW_NONE,
                                                                   0 };

    PK11AttrFlags 				   pk11AttrGenMasterKeyFlags	= PK11_ATTR_TOKEN | PK11_ATTR_PRIVATE | PK11_ATTR_SENSITIVE;

    unsigned char                   ivZerosData[AES_CBC_IV_LENGTH];
    SECItem                         ivZerosItem;
    SECItem                        *ivZerosParam = NULL;


    /**************************/
    /* Parse the command line */
    /**************************/

    secuCommand pistool;
    pistool.numCommands = sizeof( tkstool_commands ) /
                          sizeof( secuCommandFlag );
    pistool.numOptions  = sizeof( tkstool_options ) /
                          sizeof( secuCommandFlag );
    pistool.commands    = tkstool_commands;
    pistool.options     = tkstool_options;

    /* retrieve name of command */
    progName = strrchr( argv[0], '/' );
    progName = progName ? ( progName + 1 ) : argv[0];

    /* parse command line (command(s) and options) from command line */
    rvParse = SECU_ParseCommandLine( argc, argv, progName, &pistool );
    if( rvParse != SECSuccess ) {
        TKS_Usage( progName );

        return 255;
    }


    /*********************************************************/
    /* Check the number of command line "command(s)" entered */
    /*********************************************************/

    commandsEntered = 0;
    for( i = 0 ; i < pistool.numCommands ; i++ ) {
        if( pistool.commands[i].activated ) {
            commandToRun = pistool.commands[i].flag;
            commandsEntered++;
        }

        if( commandsEntered > 1 ) {
            break;
        }
    }

    if( commandsEntered > 1 ) {
        PR_fprintf( PR_STDERR,
                    "%s: only one command at a time!\n",
                    progName );

        PR_fprintf( PR_STDERR,
                    "You entered: " );

        for( i = 0 ; i < pistool.numCommands ; i++ ) {
            if( pistool.commands[i].activated ) {
                PR_fprintf( PR_STDERR,
                            " -%c",
                            pistool.commands[i].flag );
            }
        }

        PR_fprintf( PR_STDERR,
                    "\n" );
        return 255;
    }

    if( commandsEntered == 0 ) {
        PR_fprintf( PR_STDERR,
                    "%s: you must enter one of the following commands:\n\n",
                    progName );

        TKS_Usage( progName );

        return 255;
    }


    /********************************************************/
    /* Check the number of command line "option(s)" entered */
    /********************************************************/

    optionsEntered = 0;
    for( i = 0 ; i < pistool.numOptions ; i++ ) {
        if( pistool.options[i].activated ) {
            optionsEntered++;
        }

        if( optionsEntered > 1 ) {
            break;
        }
    }

    if( optionsEntered == 0                           &&
        ! ( pistool.commands[cmd_PrintHelp].activated ||
            pistool.commands[cmd_Version].activated ) ) {
        PR_fprintf( PR_STDERR,
                    "%s -%c: you must enter the following options "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }


    /***************************************************/
    /* Check that command line "options" correspond to */
    /* one of their specified command line "commands"  */
    /***************************************************/

    /* the "-d DBDir" command option may ONLY be used with */
    /* the "-D", "-I", "-K", "-L", "-M", "-N", "-P", "-R", */
    /* "-S", "-T", "-U", and "-W" commands                 */
    if( pistool.options[opt_DBDir].activated                     &&
        ! ( pistool.commands[cmd_DeleteKey].activated            ||
            pistool.commands[cmd_InputGenTransportKey].activated ||
            pistool.commands[cmd_DisplayKCV].activated           ||
            pistool.commands[cmd_ListKeys].activated             ||
            pistool.commands[cmd_GenMasterKey].activated         ||
            pistool.commands[cmd_NewDBs].activated               ||
            pistool.commands[cmd_ChangePassword].activated       ||
            pistool.commands[cmd_RenameKey].activated            ||
            pistool.commands[cmd_ListSecModules].activated       ||
            pistool.commands[cmd_GenTransportKey].activated      ||
            pistool.commands[cmd_UnWrapMasterKey].activated      ||
            pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-d DBDir\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-f pwfile" command option may ONLY be used with */
    /* the "-D", "-I", "-K", "-L", "-M", "-N", "-P", "-R",  */
    /* "-T", "-U", and "-W" commands                        */
    if( pistool.options[opt_PasswordFile].activated              &&
        ! ( pistool.commands[cmd_DeleteKey].activated            ||
            pistool.commands[cmd_InputGenTransportKey].activated ||
            pistool.commands[cmd_DisplayKCV].activated           ||
            pistool.commands[cmd_ListKeys].activated             ||
            pistool.commands[cmd_GenMasterKey].activated         ||
            pistool.commands[cmd_NewDBs].activated               ||
            pistool.commands[cmd_ChangePassword].activated       ||
            pistool.commands[cmd_RenameKey].activated            ||
            pistool.commands[cmd_GenTransportKey].activated      ||
            pistool.commands[cmd_UnWrapMasterKey].activated      ||
            pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-f pwfile\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-h token_name" command option may ONLY be used with */
    /* the "-D", "-I", "-K", "-L", "-M", "-R", "-T", "-U", and  */
    /* "-W" commands                                            */
    if( pistool.options[opt_TokenName].activated                 &&
        ! ( pistool.commands[cmd_DeleteKey].activated            ||
            pistool.commands[cmd_InputGenTransportKey].activated ||
            pistool.commands[cmd_DisplayKCV].activated           ||
            pistool.commands[cmd_ListKeys].activated             ||
            pistool.commands[cmd_GenMasterKey].activated         ||
            pistool.commands[cmd_RenameKey].activated            ||
            pistool.commands[cmd_GenTransportKey].activated      ||
            pistool.commands[cmd_UnWrapMasterKey].activated      ||
            pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-h token_name\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-i infile" command option may ONLY be used with */
    /* the "-U" command                                     */
    if( pistool.options[opt_InFile].activated            &&
        !pistool.commands[cmd_UnWrapMasterKey].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-i infile\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-n keyname" command option may ONLY be used with the */
    /* "-D", "-I", "-K", "-L", "-M", "-R", "-T", "-U", and "-W"  */
    /* commands                                                  */
    if( pistool.options[opt_Keyname].activated                   &&
        ! ( pistool.commands[cmd_DeleteKey].activated            ||
            pistool.commands[cmd_InputGenTransportKey].activated ||
            pistool.commands[cmd_DisplayKCV].activated           ||
            pistool.commands[cmd_ListKeys].activated             ||
            pistool.commands[cmd_GenMasterKey].activated         ||
            pistool.commands[cmd_RenameKey].activated            ||
            pistool.commands[cmd_GenTransportKey].activated      ||
            pistool.commands[cmd_UnWrapMasterKey].activated      ||
            pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-n keyname\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-o outfile" command option may ONLY be used with */
    /* the "-W" command                                      */
    if( pistool.options[opt_OutFile].activated         &&
        !pistool.commands[cmd_WrapMasterKey].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-o outfile\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-p DBPrefix" command option may ONLY be used with */
    /* the "-D", "-I", "-K", "-L", "-M", "-N", "-P", "-R",    */
    /* "-S", "-T", "-U", and "-W" commands                    */
    if( pistool.options[opt_DBPrefix].activated                  &&
        ! ( pistool.commands[cmd_DeleteKey].activated            ||
            pistool.commands[cmd_InputGenTransportKey].activated ||
            pistool.commands[cmd_DisplayKCV].activated           ||
            pistool.commands[cmd_ListKeys].activated             ||
            pistool.commands[cmd_GenMasterKey].activated         ||
            pistool.commands[cmd_NewDBs].activated               ||
            pistool.commands[cmd_ChangePassword].activated       ||
            pistool.commands[cmd_RenameKey].activated            ||
            pistool.commands[cmd_ListSecModules].activated       ||
            pistool.commands[cmd_GenTransportKey].activated      ||
            pistool.commands[cmd_UnWrapMasterKey].activated      ||
            pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-p DBPrefix\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-r new_keyname" command option may */
    /* ONLY be used with the "-R" command      */
    if( pistool.options[opt_NewKeyname].activated &&
        ! ( pistool.commands[cmd_RenameKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-r new_keyname\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-t transport_keyname" command option may ONLY be used with */
    /* the "-U", and "-W" commands                                     */
    if( pistool.options[opt_TransportKeyname].activated    &&
        !( pistool.commands[cmd_UnWrapMasterKey].activated ||
           pistool.commands[cmd_WrapMasterKey].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-t transport_keyname\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-x" command option may ONLY be used with */
    /* the "-L", and "-S" commands                   */
    if( pistool.options[opt_RW].activated                  &&
        ! ( pistool.commands[cmd_ListKeys].activated       ||
            pistool.commands[cmd_ListSecModules].activated ) ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-x\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /* the "-z noisefile" command option may ONLY be used with */
    /* the "-T" command                                        */
    if( pistool.options[opt_NoiseFile].activated         &&
        !pistool.commands[cmd_GenTransportKey].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-z noisefile\" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }


    /* the "-s" command option may only be used with the -M and -I command */

    if( pistool.options[opt_NonExportable].activated 	&&
    	!(pistool.commands[cmd_GenMasterKey].activated || pistool.commands[cmd_InputGenTransportKey].activated) ){

        PR_fprintf( PR_STDERR,
                    "%s -%c: the \"-s \" option may only be "
                    "specified with one of the following command(s):\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

    	return 255;
    }


    /********************************************************/
    /* Perform special processing on command line "options" */
    /********************************************************/

    /* "-a algorithm" command option */
    if(pistool.options[opt_KeyAlg].activated)
    {
        char *keyAlgStr = pistool.options[opt_KeyAlg].arg;
        if(keyAlgStr == NULL)
        {
            PR_fprintf(PR_STDERR, "%s -%c: the \"-a\" option must contain "
                    "an argument, either " ALG_AES " or " ALG_DES "\n\n",
                    progName,
                    commandToRun);
            return 255;
        }
        else
        {
            if(PL_strcmp(keyAlgStr, ALG_AES) == 0)
                keyAlg = KEY_ALG_AES;
            else if(PL_strcmp(keyAlgStr, ALG_DES) == 0)
                keyAlg = KEY_ALG_DES;
            else
            {
                PR_fprintf(PR_STDERR, "%s -%c: the \"-a\" option must specify "
                        ALG_AES " or " ALG_DES "\n\n",
                        progName,
                        commandToRun);
                return 255;
            }
        }
    }

    /* "-d DBDir" command option */
    if( pistool.options[opt_DBDir].activated ) {
        if( pistool.options[opt_DBDir].arg ) {
            DBDir = SECU_ConfigDirectory( pistool.options[opt_DBDir].arg );
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-d\" option must contain a "
                        "\"DBDir\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-f pwfile" command option */
    if( pistool.options[opt_PasswordFile].activated ) {
        pwdata.source = PW_FROMFILE;
        if( pistool.options[opt_PasswordFile].arg ) {
            pwdata.data = pistool.options[opt_PasswordFile].arg;
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-f\" option must contain a "
                        "\"pwfile\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-i infile" command option */
    if( pistool.options[opt_InFile].activated ) {
        if( pistool.options[opt_InFile].arg ) {
            input = pistool.options[opt_InFile].arg;
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-i\" option must contain an "
                        "\"infile\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-h token_name" command option */
    if( pistool.options[opt_TokenName].activated ) {
        if( pistool.options[opt_TokenName].arg ) {
            if( PL_strcmp( pistool.options[opt_TokenName].arg, "all" ) == 0 ) {
                slotname = NULL;
            } else {
                slotname = PL_strdup( pistool.options[opt_TokenName].arg );
            }
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-h\" option must contain a "
                        "\"token_name\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-l key_length_bits" command option */
    if(pistool.options[opt_KeyLength].activated)
    {
        char *keyLengthStr = pistool.options[opt_KeyLength].arg;
        if(keyLengthStr == NULL && keyAlg == KEY_ALG_AES)
        {
            PR_fprintf(PR_STDERR, "%s -%c: the \"-l\" option must specify "
                    "the desired bit length of the AES key as an integer\n\n",
                    progName,
                    commandToRun);
            return 255;
        }

        // String to unsigned long, base-10
        keyLength = strtoul(keyLengthStr, NULL, 10);
    }
    else if(keyAlg == KEY_ALG_AES)
    {
        /*
        PR_fprintf(PR_STDERR, "%s -%c: when creating an AES key, the "
                "\"-l\" option must be used to specify the "
                "desired length of the AES key in bits\n\n",
                progName,
                commandToRun);
        return 255;
        */
        keyLength = 128;
    }

    /* "-n keyname" command option */
    if( pistool.options[opt_Keyname].activated ) {
        if( pistool.options[opt_Keyname].arg ) {
            keyname = SECU_GetOptionArg( &pistool,
                                         opt_Keyname );
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-n\" option must contain a "
                        "\"keyname\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-o outfile" command option */
    if( pistool.options[opt_OutFile].activated ) {
        if( pistool.options[opt_OutFile].arg ) {
            output = pistool.options[opt_OutFile].arg;
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-o\" option must contain an "
                        "\"outfile\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-p DBPrefix" command option */
    if( pistool.options[opt_DBPrefix].activated ) {
        if( pistool.options[opt_DBPrefix].arg ) {
            DBPrefix = strdup( pistool.options[opt_DBPrefix].arg );
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-p\" option must contain a "
                        "\"DBPrefix\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-r new_keyname" command option */
    if( pistool.options[opt_NewKeyname].activated ) {
        if( pistool.options[opt_NewKeyname].arg ) {
            new_keyname = SECU_GetOptionArg( &pistool,
                                             opt_NewKeyname );
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-r\" option must contain a "
                        "\"new_keyname\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-t transport_keyname" command option */
    if( pistool.options[opt_TransportKeyname].activated ) {
        if( pistool.options[opt_TransportKeyname].arg ) {
            transport_keyname = SECU_GetOptionArg( &pistool,
                                                   opt_TransportKeyname );
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-t\" option must contain a "
                        "\"transport_keyname\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }

    /* "-x" command option is processed below */
    /*      ONLY based upon specific commands */

    /* "-z noisefile" command option */
    if( pistool.options[opt_NoiseFile].activated ) {
        if( pistool.options[opt_NoiseFile].arg ) {
            SeedNoise = pistool.options[opt_NoiseFile].arg;
        } else {
            PR_fprintf( PR_STDERR, 
                        "%s -%c: the \"-z\" option must contain a "
                        "\"noisefile\" argument:\n\n",
                        progName,
                        commandToRun );

            TKS_Usage( progName );

            return 255;
        }
    }


    //PAS MOD FE3
    /* "-s" command option ultimately sets CKA_EXTRACTABLE to false on key gen*/
    if( pistool.options[opt_NonExportable].activated){

    	pk11AttrGenMasterKeyFlags |= PK11_ATTR_UNEXTRACTABLE;

    }


    /******************************************************************/
    /* Perform special processing on specific command line "commands" */
    /******************************************************************/

    /* "-M", I, T, U, and W commands require the "-a algorithm" option
     * to be specified */
    if((pistool.commands[cmd_GenMasterKey].activated            ||
        pistool.commands[cmd_InputGenTransportKey].activated    ||
        pistool.commands[cmd_GenTransportKey].activated         ||
        pistool.commands[cmd_UnWrapMasterKey].activated         ||
        pistool.commands[cmd_WrapMasterKey].activated         ) &&
            !pistool.options[opt_KeyAlg].activated)
    {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-a algorithm\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-D", "-I", "-K", "-M", "-R", "-T", "-U" and "-W" */
    /*  commands require the "-n keyname" command line    */
    /*  option to be specified                            */
    if( ( pistool.commands[cmd_DeleteKey].activated            ||
          pistool.commands[cmd_InputGenTransportKey].activated ||
          pistool.commands[cmd_DisplayKCV].activated           ||
          pistool.commands[cmd_GenMasterKey].activated         ||
          pistool.commands[cmd_RenameKey].activated            ||
          pistool.commands[cmd_GenTransportKey].activated      ||
          pistool.commands[cmd_UnWrapMasterKey].activated      ||
          pistool.commands[cmd_WrapMasterKey].activated )      &&
        !pistool.options[opt_Keyname].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-n keyname\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-D", "-I", "-K", "-L", "-M", "-N", "-P", "-R", "-S", */
    /*  "-T", "-U", and "-W" commands require the "-d DBDir"  */
    /*  command line option to be specified                   */
    if( ( pistool.commands[cmd_DeleteKey].activated            ||
          pistool.commands[cmd_InputGenTransportKey].activated ||
          pistool.commands[cmd_DisplayKCV].activated           ||
          pistool.commands[cmd_ListKeys].activated             ||
          pistool.commands[cmd_GenMasterKey].activated         ||
          pistool.commands[cmd_NewDBs].activated               ||
          pistool.commands[cmd_ChangePassword].activated       ||
          pistool.commands[cmd_RenameKey].activated            ||
          pistool.commands[cmd_ListSecModules].activated       ||
          pistool.commands[cmd_GenTransportKey].activated      ||
          pistool.commands[cmd_UnWrapMasterKey].activated      ||
          pistool.commands[cmd_WrapMasterKey].activated )      &&
        !pistool.options[opt_DBDir].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-d DBDir\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-H", "-L", "-S", and "-V" commands require the "-x" */
    /*  command line option to be silently turned off        */
    if( pistool.commands[cmd_PrintHelp].activated      ||
        pistool.commands[cmd_ListKeys].activated       ||
        pistool.commands[cmd_ListSecModules].activated ||
        pistool.commands[cmd_Version].activated ) {
        readOnly = !pistool.options[opt_RW].activated;
    }

    /*  "-L" command is the ONLY command that allows */
    /*  the "-h all" command line option to be used  */
    /*                                               */
    /*  NOTE:  ONLY use "slotname == NULL" to        */
    /*         LIST keys on all slots                */
    if( !pistool.commands[cmd_ListKeys].activated && slotname == NULL ) {
        PR_fprintf( PR_STDERR,
                    "%s -%c: cannot use \"-h all\" for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-R" commands require the "-r new_keyname" */
    /*  command line option to be specified        */
    if( ( pistool.commands[cmd_RenameKey].activated ) &&
        !pistool.options[opt_NewKeyname].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-r new_keyname\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-U", and "-W" commands require the "-t transport_keyname" */
    /*  command line option to be specified                        */
    if( ( pistool.commands[cmd_UnWrapMasterKey].activated ||
          pistool.commands[cmd_WrapMasterKey].activated ) &&
        !pistool.options[opt_TransportKeyname].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-t transport_keyname\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-U" commands require the "-i infile" */
    /*  command line option to be specified   */
    if( pistool.commands[cmd_UnWrapMasterKey].activated &&
        !pistool.options[opt_InFile].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-i infile\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }

    /*  "-W" commands require the "-o outfile" */
    /*  command line option to be specified    */
    if( pistool.commands[cmd_WrapMasterKey].activated &&
        !pistool.options[opt_OutFile].activated ) {
        PR_fprintf( PR_STDERR, 
                    "%s -%c: the \"-o outfile\" option is required "
                    "for this command:\n\n",
                    progName,
                    commandToRun );

        TKS_Usage( progName );

        return 255;
    }


    /*********************************/
    /* Execute the "-H" help command */
    /*********************************/

    if( pistool.commands[cmd_PrintHelp].activated ) {
        TKS_PrintHelp( progName );

        return 0;
    }


    /************************************/
    /* Execute the "-V" version command */
    /************************************/

    /* "-V" version command */
    if( pistool.commands[cmd_Version].activated ) {
        TKS_Version( progName );

        return 0;
    }


    /************************************************/
    /* Initialize PKCS #11 Security Module Password */
    /************************************************/

    PK11_SetPasswordFunc( /* password callback */  SECU_GetModulePassword );


    /*******************/
    /* Initialize NSPR */
    /*******************/

    PR_Init( PR_SYSTEM_THREAD,
             PR_PRIORITY_NORMAL,
             1 );


    /******************/
    /* Initialize NSS */
    /******************/

    rvNSSinit = NSS_Initialize( SECU_ConfigDirectory( NULL ),
                                DBPrefix,
                                DBPrefix,
                                "secmod.db",
                                readOnly ? NSS_INIT_READONLY : 0 );
    if( rvNSSinit != SECSuccess ) {
        char    buffer[513];
        PRInt32 errLen = PR_GetErrorTextLength();

        if( errLen > 0 && errLen < sizeof buffer ) {
            PR_GetErrorText( buffer );
        }

        PR_fprintf( PR_STDERR,
                    "%s -%c:  %s",
                    progName,
                    commandToRun,
                    "NSS_Initialize() failed" );

        if( errLen > 0 && errLen < sizeof buffer ) {
            PR_fprintf( PR_STDERR, "\t%s\n", buffer );
        } else {
            PR_fprintf( PR_STDERR, "\n" );
        }

        rv = SECFailure;
        goto shutdown;
    }


    /*****************************************************/
    /* Initialize internal PKCS #11 software crypto slot */
    /* as well as any specified PKCS #11 slot            */
    /*****************************************************/

    /* Always initialize the internal software crypto slot */
    internalSlot = PK11_GetInternalSlot();

    /* If "slotname != NULL", initialize the slot based upon the slotname */
    if( PL_strcmp( slotname, "internal" ) == 0 ) {
        slot = PK11_GetInternalKeySlot();
    } else if( slotname != NULL ) {
        slot = PK11_FindSlotByName( /* slot name */  slotname );

        /* Fixes Bugscape Bug #55178: pistool dumps core if -h <token> */
        /*                            specifies a nonexistent token    */
        if( slot == NULL ) {
            char    buffer[513];
            PRInt32 errLen = PR_GetErrorTextLength();

            if( errLen > 0 && errLen < sizeof buffer ) {
                PR_GetErrorText( buffer );
            }

            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s%s%s",
                        progName,
                        commandToRun,
                        "no token called \"",
                        slotname,
                        "\" exists!" );

            if( errLen > 0 && errLen < sizeof buffer ) {
                PR_fprintf( PR_STDERR, "\t%s\n", buffer );
            } else {
                PR_fprintf( PR_STDERR, "\n" );
            }

            rv = SECFailure;
            goto shutdown;
        }
    }

    /*
     * Initialize the initialization vector of zeros for AES
     */
    PORT_Memset(ivZerosData, 0, sizeof(ivZerosData));

    ivZerosItem.type = siBuffer;
    ivZerosItem.data = ivZerosData;
    ivZerosItem.len = AES_CBC_IV_LENGTH;

    ivZerosParam = PK11_ParamFromIV(CKM_AES_CBC, &ivZerosItem);
    if(ivZerosParam == NULL)
    {
        PR_fprintf(PR_STDERR, "ERROR %i: Failed to create iv param\n\n",
                PR_GetError());
        rv = SECFailure;
        goto shutdown;
    }

    /****************************************/
    /* Execute the "-D" delete keys command */
    /*                                      */
    /* NOTE:  This command is mutually      */
    /*        exclusive from all others.    */
    /****************************************/

    if( pistool.commands[cmd_DeleteKey].activated ) {
        rv = TKS_DeleteKeys( progName,
                             slot,
                             keyname,
                             &pwdata );
        goto shutdown;
    }


    /*******************************************************************/
    /* Execute the "-I" input shares to generate transport key command */
    /*                                                                 */
    /*                 ---  OR  ---                                    */
    /*                                                                 */
    /* Execute the "-T" generate transport key command                 */
    /*                                                                 */
    /* NOTE:  Each of these commands is mutually                       */
    /*        exclusive from all others, including                     */
    /*        each other.                                              */
    /*******************************************************************/

    if( pistool.commands[cmd_InputGenTransportKey].activated ||
        pistool.commands[cmd_GenTransportKey].activated ) {

        /**********************************************************/
        /*  Do not allow duplicate symmetric keys to be generated */
        /*  (i. e. - disallow symmetric keys specified            */
        /*           by the same keyname)                         */
        /*                                                        */
        /*  NOTE:  The following code snippet effectively         */
        /*         prohibits this tool from generating any        */
        /*         symmetric key with a keyname that already      */
        /*         resides in the specified token                 */
        /**********************************************************/

        rvFindSymKey = TKS_FindSymKey( slot,
                                       keyname,
                                       &pwdata );
        if( rvFindSymKey == SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" keyname specified by "
                        "\n\t\t\"-n %s\"\n\t\talready exists in the "
                        "specified token.\n\t\tPlease specify a "
                        "different keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /**********************************************/
        /* Seed the Random Number Generator (RNG).    */
        /* ("-T" generate transport key command ONLY) */
        /**********************************************/

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            rvSeedRNG = TKS_SeedRNG( SeedNoise );
            if( rvSeedRNG != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s",
                            progName,
                            commandToRun,
                            "unable to seed random number generator\n" );
                rv = SECFailure;
                goto shutdown;
            }
        }


        /***********************************/
        /* Clear screen and wait for user. */
        /***********************************/

        TKS_ClearScreen();

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            PR_fprintf( PR_STDOUT,
                        "\nThe next screen generates the "
                        "first session key share . . .\n" );
        } else {
            /* ( tkstool.commands[cmd_InputGenTransportKey].activated ) */
            PR_fprintf( PR_STDOUT,
                        "\nUse the next screen to input the "
                        "first session key share . . .\n" );
        }

        TKS_TypeProceedToContinue();


        /******************************************************************/
        /* Input ("-I"), or Generate ("-T"), the first session key share. */
        /******************************************************************/

        firstSessionKeyShare.len    = FIRST_SESSION_KEY_SHARE_LENGTH;
        firstSessionKeyShare.data   = ( unsigned char * )
                                      PORT_ZAlloc( FIRST_SESSION_KEY_SHARE_LENGTH );

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            rvFirstSessionKeyShare = TKS_GenerateSessionKeyShare(
                                         FIRST_SESSION_KEY_SHARE,
                                         &firstSessionKeyShare,
                                         keyAlg );

            if( rvFirstSessionKeyShare != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s",
                            progName,
                            commandToRun,
                            "unable to generate the ",
                            FIRST_SESSION_KEY_SHARE,
                            " session key share\n" );
                rv = SECFailure;
                goto shutdown;
            }
        } else {
            /* ( pistool.commands[cmd_InputGenTransportKey].activated ) */
            while( rvFirstSessionKeyShare != SECSuccess ) {
                rvFirstSessionKeyShare = TKS_InputSessionKeyShare(
                                             FIRST_SESSION_KEY_SHARE,
                                             &firstSessionKeyShare,
                                             keyAlg );
            }
        }

#if defined(PAD_DES2_KEY_LENGTH)
        if(keyAlg == KEY_ALG_DES)
        {
            /****************************************************************/
            /* Since TKS uses double-DES keys instead of triple-DES keys,   */
            /* the final 8 bytes of this session key share must be padded   */
            /* in order to use the standard PKCS #11 triple-DES operations! */
            /*                                                              */
            /* Therefore, in order to perform this operation, the 16 bytes  */
            /* comprising the original buffer are first copied into the new */
            /* buffer, and then the first 8 bytes of the original buffer    */
            /* are copied into the final 8 bytes of the new buffer.         */
            /****************************************************************/

            paddedFirstSessionKeyShare.len  = PADDED_FIRST_SESSION_KEY_SHARE_LENGTH;
            paddedFirstSessionKeyShare.data = ( unsigned char * )
                                              PORT_ZAlloc( PADDED_FIRST_SESSION_KEY_SHARE_LENGTH );

            PORT_Memcpy( paddedFirstSessionKeyShare.data,
                         firstSessionKeyShare.data,
                         FIRST_SESSION_KEY_SHARE_LENGTH );
            PORT_Memcpy( ( paddedFirstSessionKeyShare.data +
                           FIRST_SESSION_KEY_SHARE_LENGTH ),
                         firstSessionKeyShare.data,
                         DES_LENGTH );
        }
#endif


        /***********************************/
        /* Clear screen and wait for user. */
        /***********************************/

        TKS_ClearScreen();

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            PR_fprintf( PR_STDOUT,
                        "\nThe next screen generates the "
                        "second session key share . . .\n" );
        } else {
            /* ( tkstool.commands[cmd_InputGenTransportKey].activated ) */
            PR_fprintf( PR_STDOUT,
                        "\nUse the next screen to input the "
                        "second session key share . . .\n" );
        }

        TKS_TypeProceedToContinue();


        /*******************************************************************/
        /* Input ("-I"), or Generate ("-T"), the second session key share. */
        /*******************************************************************/

        secondSessionKeyShare.len  = SECOND_SESSION_KEY_SHARE_LENGTH;
        secondSessionKeyShare.data = ( unsigned char * )
                                     PORT_ZAlloc( SECOND_SESSION_KEY_SHARE_LENGTH );

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            rvSecondSessionKeyShare = TKS_GenerateSessionKeyShare(
                                          SECOND_SESSION_KEY_SHARE,
                                          &secondSessionKeyShare,
                                          keyAlg );

            if( rvSecondSessionKeyShare != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s",
                            progName,
                            commandToRun,
                            "unable to generate the ",
                            SECOND_SESSION_KEY_SHARE,
                            " session key share\n" );
                rv = SECFailure;
                goto shutdown;
            }
        } else {
            /* ( pistool.commands[cmd_InputGenTransportKey].activated ) */
            while( rvSecondSessionKeyShare != SECSuccess ) {
                rvSecondSessionKeyShare = TKS_InputSessionKeyShare(
                                              SECOND_SESSION_KEY_SHARE,
                                              &secondSessionKeyShare,
                                              keyAlg );
            }
        }

#if defined(PAD_DES2_KEY_LENGTH)
        if(keyAlg == KEY_ALG_DES)
        {
            /****************************************************************/
            /* Since TKS uses double-DES keys instead of triple-DES keys,   */
            /* the final 8 bytes of this session key share must be padded   */
            /* in order to use the standard PKCS #11 triple-DES operations! */
            /*                                                              */
            /* Therefore, in order to perform this operation, the 16 bytes  */
            /* comprising the original buffer are first copied into the new */
            /* buffer, and then the first 8 bytes of the original buffer    */
            /* are copied into the final 8 bytes of the new buffer.         */
            /****************************************************************/

            paddedSecondSessionKeyShare.len  = PADDED_SECOND_SESSION_KEY_SHARE_LENGTH;
            paddedSecondSessionKeyShare.data = ( unsigned char * )
                                               PORT_ZAlloc( PADDED_SECOND_SESSION_KEY_SHARE_LENGTH );

            PORT_Memcpy( paddedSecondSessionKeyShare.data,
                         secondSessionKeyShare.data,
                         SECOND_SESSION_KEY_SHARE_LENGTH );
            PORT_Memcpy( ( paddedSecondSessionKeyShare.data +
                           SECOND_SESSION_KEY_SHARE_LENGTH ),
                         secondSessionKeyShare.data,
                         DES_LENGTH );


            /**********************************************/
            /* Prepare this key share to be used with the */
            /* TKS_DeriveSymmetricKey() function . . .    */
            /**********************************************/

            /* store a copy of the "original" padded second session key share */
            secondDerivationData.ulLen = paddedSecondSessionKeyShare.len;
            secondDerivationData.pData = ( unsigned char * )
                                         PORT_ZAlloc( paddedSecondSessionKeyShare.len );
            PORT_Memcpy( secondDerivationData.pData,
                         paddedSecondSessionKeyShare.data,
                         paddedSecondSessionKeyShare.len );

            /* destroy the "original" padded second session key share */
            if( paddedSecondSessionKeyShare.data != NULL ) {
                PORT_ZFree( ( unsigned char * )
                            paddedSecondSessionKeyShare.data,
                            paddedSecondSessionKeyShare.len );
                paddedSecondSessionKeyShare.data = NULL;
                paddedSecondSessionKeyShare.len  = 0;
            }

            /* create a "new" container for the padded second session key share */
            paddedSecondSessionKeyShare.len  = sizeof( CK_KEY_DERIVATION_STRING_DATA );
            paddedSecondSessionKeyShare.data = ( unsigned char * )
                                               PORT_ZAlloc( paddedSecondSessionKeyShare.len );

            /* copy the "original" padded second session key share */
            /* into the "new" container                            */
            PORT_Memcpy( paddedSecondSessionKeyShare.data,
                         &secondDerivationData,
                         paddedSecondSessionKeyShare.len );
        }
#else
        /**********************************************/
        /* Prepare this key share to be used with the */
        /* TKS_DeriveSymmetricKey() function . . .    */
        /**********************************************/

        /* store a copy of the "original" second session key share */
        secondDerivationData.ulLen = secondSessionKeyShare.len;
        secondDerivationData.pData = ( unsigned char * )
                                     PORT_ZAlloc( secondSessionKeyShare.len );
        PORT_Memcpy( secondDerivationData.pData,
                     secondSessionKeyShare.data,
                     secondSessionKeyShare.len );

        /* destroy the "original" second session key share */
        if( secondSessionKeyShare.data != NULL ) {
            PORT_ZFree( ( unsigned char * )
                        secondSessionKeyShare.data,
                        secondSessionKeyShare.len );
            secondSessionKeyShare.data = NULL;
            secondSessionKeyShare.len  = 0;
        }

        /* create a "new" container for the second session key share */
        secondSessionKeyShare.len  = sizeof( CK_KEY_DERIVATION_STRING_DATA );
        secondSessionKeyShare.data = ( unsigned char * )
                                     PORT_ZAlloc( secondSessionKeyShare.len );

        /* copy the "original" second session key share */
        /* into the "new" container                     */
        PORT_Memcpy( secondSessionKeyShare.data,
                     &secondDerivationData,
                     secondSessionKeyShare.len );
#endif


        /***********************************/
        /* Clear screen and wait for user. */
        /***********************************/

        TKS_ClearScreen();

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            PR_fprintf( PR_STDOUT,
                        "\nThe next screen generates the "
                        "third session key share . . .\n" );
        } else {
            /* ( tkstool.commands[cmd_InputGenTransportKey].activated ) */
            PR_fprintf( PR_STDOUT,
                        "\nUse the next screen to input the "
                        "third session key share . . .\n" );
        }

        TKS_TypeProceedToContinue();


        /******************************************************************/
        /* Input ("-I"), or Generate ("-T"), the third session key share. */
        /******************************************************************/

        thirdSessionKeyShare.len  = THIRD_SESSION_KEY_SHARE_LENGTH;
        thirdSessionKeyShare.data = ( unsigned char * )
                                    PORT_ZAlloc( THIRD_SESSION_KEY_SHARE_LENGTH );

        if( pistool.commands[cmd_GenTransportKey].activated ) {
            rvThirdSessionKeyShare = TKS_GenerateSessionKeyShare(
                                         THIRD_SESSION_KEY_SHARE,
                                         &thirdSessionKeyShare,
                                         keyAlg );

            if( rvThirdSessionKeyShare != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s",
                            progName,
                            commandToRun,
                            "unable to generate the ",
                            THIRD_SESSION_KEY_SHARE,
                            " session key share\n" );
                rv = SECFailure;
                goto shutdown;
            }
        } else {
            /* ( pistool.commands[cmd_InputGenTransportKey].activated ) */
            while( rvThirdSessionKeyShare != SECSuccess ) {
                rvThirdSessionKeyShare = TKS_InputSessionKeyShare(
                                             THIRD_SESSION_KEY_SHARE,
                                             &thirdSessionKeyShare,
                                             keyAlg );
            }
        }

#if defined(PAD_DES2_KEY_LENGTH)
        if(keyAlg == KEY_ALG_DES)
        {
            /****************************************************************/
            /* Since TKS uses double-DES keys instead of triple-DES keys,   */
            /* the final 8 bytes of this session key share must be padded   */
            /* in order to use the standard PKCS #11 triple-DES operations! */
            /*                                                              */
            /* Therefore, in order to perform this operation, the 16 bytes  */
            /* comprising the original buffer are first copied into the new */
            /* buffer, and then the first 8 bytes of the original buffer    */
            /* are copied into the final 8 bytes of the new buffer.         */
            /****************************************************************/

            paddedThirdSessionKeyShare.len  = PADDED_THIRD_SESSION_KEY_SHARE_LENGTH;
            paddedThirdSessionKeyShare.data = ( unsigned char * )
                                               PORT_ZAlloc( PADDED_THIRD_SESSION_KEY_SHARE_LENGTH );

            PORT_Memcpy( paddedThirdSessionKeyShare.data,
                         thirdSessionKeyShare.data,
                         THIRD_SESSION_KEY_SHARE_LENGTH );
            PORT_Memcpy( ( paddedThirdSessionKeyShare.data +
                           THIRD_SESSION_KEY_SHARE_LENGTH ),
                         thirdSessionKeyShare.data,
                         DES_LENGTH );


            /**********************************************/
            /* Prepare this key share to be used with the */
            /* TKS_DeriveSymmetricKey() function . . .    */
            /**********************************************/

            /* store a copy of the "original" padded third session key share */
            thirdDerivationData.ulLen = paddedThirdSessionKeyShare.len;
            thirdDerivationData.pData = ( unsigned char * )
                                        PORT_ZAlloc( paddedThirdSessionKeyShare.len );
            PORT_Memcpy( thirdDerivationData.pData,
                         paddedThirdSessionKeyShare.data,
                         paddedThirdSessionKeyShare.len );

            /* destroy the "original" padded third session key share */
            if( paddedThirdSessionKeyShare.data != NULL ) {
                PORT_ZFree( ( unsigned char * )
                            paddedThirdSessionKeyShare.data,
                            paddedThirdSessionKeyShare.len );
                paddedThirdSessionKeyShare.data = NULL;
                paddedThirdSessionKeyShare.len  = 0;
            }

            /* create a "new" container for the padded third session key share */
            paddedThirdSessionKeyShare.len  = sizeof( CK_KEY_DERIVATION_STRING_DATA );
            paddedThirdSessionKeyShare.data = ( unsigned char * )
                                              PORT_ZAlloc( paddedThirdSessionKeyShare.len );

            /* copy the "original" padded third session key share */
            /* into the "new" container                           */
            PORT_Memcpy( paddedThirdSessionKeyShare.data,
                         &thirdDerivationData,
                         paddedThirdSessionKeyShare.len );
        }
#else
        /**********************************************/
        /* Prepare this key share to be used with the */
        /* TKS_DeriveSymmetricKey() function . . .    */
        /**********************************************/

        /* store a copy of the "original" third session key share */
        thirdDerivationData.ulLen = thirdSessionKeyShare.len;
        thirdDerivationData.pData = ( unsigned char * )
                                    PORT_ZAlloc( thirdSessionKeyShare.len );
        PORT_Memcpy( thirdDerivationData.pData,
                     thirdSessionKeyShare.data,
                     thirdSessionKeyShare.len );

        /* destroy the "original" third session key share */
        if( thirdSessionKeyShare.data != NULL ) {
            PORT_ZFree( ( unsigned char * )
                        thirdSessionKeyShare.data,
                        thirdSessionKeyShare.len );
            thirdSessionKeyShare.data = NULL;
            thirdSessionKeyShare.len  = 0;
        }

        /* create a "new" container for the third session key share */
        thirdSessionKeyShare.len  = sizeof( CK_KEY_DERIVATION_STRING_DATA );
        thirdSessionKeyShare.data = ( unsigned char * )
                                    PORT_ZAlloc( thirdSessionKeyShare.len );

        /* copy the "original" third session key share */
        /* into the "new" container                           */
        PORT_Memcpy( thirdSessionKeyShare.data,
                     &thirdDerivationData,
                     thirdSessionKeyShare.len );
#endif


        /***********************************/
        /* Clear screen and wait for user. */
        /***********************************/

        TKS_ClearScreen();

        PR_fprintf( PR_STDOUT,
                    "\nThe next screen uses the session key shares to "
                    "generate the transport key . . .\n" );

        TKS_TypeProceedToContinue();

        TKS_ClearScreen();


        /**************************************/
        /* Generate the first symmetric key   */
        /* using the first session key share. */
        /**************************************/


        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            firstSymmetricKey = TKS_ImportSymmetricKey(
                    FIRST_SYMMETRIC_KEY,
                    internalSlot,
                    CKM_AES_KEY_GEN,
                    CKA_ENCRYPT,
                    &firstSessionKeyShare,
                    &pwdata);

            break;
        }
        case KEY_ALG_DES:
        {
#if defined(PAD_DES2_KEY_LENGTH)
            firstSymmetricKey = TKS_ImportSymmetricKey( FIRST_SYMMETRIC_KEY,
                                                        internalSlot,
                                                        CKM_DES3_KEY_GEN,
                                                        CKA_ENCRYPT,
                                                        &paddedFirstSessionKeyShare,
                                                        &pwdata );
#else
            firstSymmetricKey = TKS_ImportSymmetricKey( FIRST_SYMMETRIC_KEY,
                                                        internalSlot,
                                                        CKM_DES2_KEY_GEN,
                                                        CKA_ENCRYPT,
                                                        &firstSessionKeyShare,
                                                        &pwdata );
#endif
            break;
        }
        default:
            break;
        }

        if( firstSymmetricKey == NULL ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to generate the first (or initial) "
                        "symmetric key",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }


        /*********************************************************/
        /* Generate the second symmetric key using the           */
        /* first symmetric key and the second session key share. */
        /*********************************************************/

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            secondSymmetricKey = TKS_DeriveSymmetricKey(
                    SECOND_SYMMETRIC_KEY,
                    firstSymmetricKey,
                    CKM_XOR_BASE_AND_DATA,
                    &secondSessionKeyShare,
                    CKM_AES_CBC,
                    (CKA_DERIVE | CKA_ENCRYPT),
                    SECOND_SESSION_KEY_SHARE_LENGTH);

            break;
        }
        case KEY_ALG_DES:
        {
#if defined(PAD_DES2_KEY_LENGTH)
            secondSymmetricKey = TKS_DeriveSymmetricKey( SECOND_SYMMETRIC_KEY,
                                                         firstSymmetricKey,
                                                         CKM_XOR_BASE_AND_DATA,
                                                         &paddedSecondSessionKeyShare,
                                                         CKM_DES3_ECB,
                                                         ( CKA_DERIVE |
                                                           CKA_ENCRYPT ),
                                                         PADDED_SECOND_SESSION_KEY_SHARE_LENGTH );
#else
            secondSymmetricKey = TKS_DeriveSymmetricKey( SECOND_SYMMETRIC_KEY,
                                                         firstSymmetricKey,
                                                         CKM_XOR_BASE_AND_DATA,
                                                         &secondSessionKeyShare,
                                                         CKM_DES3_ECB,
                                                         ( CKA_DERIVE |
                                                           CKA_ENCRYPT ),
                                                         SECOND_SESSION_KEY_SHARE_LENGTH );
#endif
            break;
        }
        default:
            break;
        }

        if( secondSymmetricKey == NULL ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to generate the second (or intermediate) "
                        "symmetric key",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }


        /*********************************************************/
        /* Generate the third symmetric key using the            */
        /* second symmetric key and the third session key share. */
        /*********************************************************/

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            thirdSymmetricKey = TKS_DeriveSymmetricKey(
                    THIRD_SYMMETRIC_KEY,
                    secondSymmetricKey,
                    CKM_XOR_BASE_AND_DATA,
                    &thirdSessionKeyShare,
                    CKM_AES_CBC,
                    (CKA_DERIVE | CKA_ENCRYPT),
                    THIRD_SESSION_KEY_SHARE_LENGTH);

            break;
        }
        case KEY_ALG_DES:
        {
#if defined(PAD_DES2_KEY_LENGTH)
            thirdSymmetricKey = TKS_DeriveSymmetricKey( THIRD_SYMMETRIC_KEY,
                                                        secondSymmetricKey,
                                                        CKM_XOR_BASE_AND_DATA,
                                                        &paddedThirdSessionKeyShare,
                                                        CKM_DES3_ECB,
                                                        ( CKA_DERIVE |
                                                          CKA_ENCRYPT ),
                                                        PADDED_THIRD_SESSION_KEY_SHARE_LENGTH );
#else
            thirdSymmetricKey = TKS_DeriveSymmetricKey( THIRD_SYMMETRIC_KEY,
                                                        secondSymmetricKey,
                                                        CKM_XOR_BASE_AND_DATA,
                                                        &thirdSessionKeyShare,
                                                        CKM_DES3_ECB,
                                                        ( CKA_DERIVE |
                                                          CKA_ENCRYPT ),
                                                        THIRD_SESSION_KEY_SHARE_LENGTH );
#endif
            break;
        }
        default:
            break;
        }

        if( thirdSymmetricKey == NULL ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to generate the third (or final) "
                        "symmetric key",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }


        /*******************************************************************/
        /* Finally, store the third symmetric key (the transport key) into */
        /* the specified slot, and provide a name for this transport key.  */
        /*******************************************************************/

        rvSymmetricKeyname = TKS_StoreSymmetricKeyAndNameIt( TRANSPORT_KEY,
                                                             keyname,
                                                             slot,
                                                             ( CKA_ENCRYPT |
                                                               CKA_WRAP ),
                                                             ( CKF_ENCRYPT |
                                                               CKF_UNWRAP  |
                                                               CKF_WRAP ),
                                                             thirdSymmetricKey,
                                                             keyAlg,
															 pistool.options[opt_NonExportable].activated); //PAS MOD FE4 in theory this is false, except for -I with -s
        if( rvSymmetricKeyname != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to save/name the transport key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        } else {
            PR_fprintf( PR_STDOUT,
                        "Successfully generated, stored, and named the "
                        "transport key!\n\n" );
        }





        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


    /****************************************/
    /* Execute the "-K" display KCV command */
    /*                                      */
    /* NOTE:  This command is mutually      */
    /*        exclusive from all others.    */
    /****************************************/

    if( pistool.commands[cmd_DisplayKCV].activated ) {

        /*****************************************************/
        /* Retrieve a handle to the specified symmetric key. */
        /* This insures that the specified symmetric key     */
        /* already resides on the specified token.           */
        /*****************************************************/

        symmetricKey = TKS_RetrieveSymKey( slot,
                                           keyname,
                                           &pwdata );
        if( symmetricKey == NULL ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" symmetric keyname specified by "
                        "\n\t\t\"-n %s\" does NOT exist on the specified "
                        "token.\n\t\tPlease specify a "
                        "different symmetric keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /*************************************************/
        /* Compute and display this symmetric key's KCV. */
        /*************************************************/

        PR_fprintf( PR_STDOUT,
                    "\nComputing and displaying KCV of the symmetric key "
                    "on the specified token . . .\n\n" );

        /* Detect the key type (AES or DES) */
        KeyAlgorithm detectedAlg = TKS_DetectKeyAlgorithm(symmetricKey);
        if(detectedAlg == KEY_ALG_UNKNOWN)
        {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to detect the algorithm of "
                        "this symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }

        PR_fprintf(PR_STDOUT, "This key is of type: ");
        switch(detectedAlg)
        {
        case KEY_ALG_AES: PR_fprintf(PR_STDOUT, ALG_AES" . . .\n\n"); break;
        case KEY_ALG_DES: PR_fprintf(PR_STDOUT, ALG_DES" . . .\n\n"); break;
        }

        /* Calculate this symmetric key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        symmetricKey,
                                                        keyname,
                                                        RESIDENT_KEY,
                                                        detectedAlg,
                                                        PR_TRUE,
                                                        NULL );
        if( rvKCV != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to compute/display KCV of "
                        "this symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }


        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


    /**************************************/
    /* Execute the "-L" list keys command */
    /*                                    */
    /* NOTE:  This command is mutually    */
    /*        exclusive from all others.  */
    /**************************************/

    if( pistool.commands[cmd_ListKeys].activated ) {
        rv = TKS_ListKeys( progName,
                           slot,
                           keyname,
                           0 /*keyindex*/,
                           PR_FALSE /*dopriv*/,
                           &pwdata );
        goto shutdown;
    }


    /************************************************/
    /* Execute the "-M" generate master key command */
    /*                                              */
    /* NOTE:  This command is mutually              */
    /*        exclusive from all others.            */
    /************************************************/

    if( pistool.commands[cmd_GenMasterKey].activated ) {

        /**********************************************************/
        /*  Do not allow duplicate symmetric keys to be generated */
        /*  (i. e. - disallow symmetric keys specified            */
        /*           by the same keyname)                         */
        /*                                                        */
        /*  NOTE:  The following code snippet effectively         */
        /*         prohibits this tool from generating any        */
        /*         symmetric key with a keyname that already      */
        /*         resides in the specified token                 */
        /**********************************************************/

        rvFindSymKey = TKS_FindSymKey( slot,
                                       keyname,
                                       &pwdata );
        if( rvFindSymKey == SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" keyname specified by "
                        "\n\t\t\"-n %s\"\n\t\talready exists in the "
                        "specified token.\n\t\tPlease specify a "
                        "different keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /*****************************************************************/
        /* Generate the master key and store it on the designated token. */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                    "\nGenerating and storing the master key "
                    "on the specified token . . .\n\n" );


        //PAS MOD FE3
        //Replaced PK11_TokenKeyGen with PK11_TokenKeyGenWithFlags so passing in a pk11Attrbute flag parameter is possible.
        //the pk11Attribute flag is set up above from here (search for '-s'

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            masterKey = PK11_TokenKeyGenWithFlags(
                    slot,
                    CKM_AES_KEY_GEN,
                    0,
                    keyLength / 8,
                    0,
                    CKA_ENCRYPT,
                    pk11AttrGenMasterKeyFlags,
                    &pwdata);

            if(masterKey == NULL)
            {
                PR_fprintf(PR_STDERR,
                        "%s -%c: %s:%d\n\n\n",
                        progName,
                        commandToRun,
                        "Unable to generate/store this AES master key",
                        PR_GetError());
                
                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        case KEY_ALG_DES:
        {
            if( MASTER_KEY_LENGTH == ( 2 * DES_LENGTH ) ) {

                masterKey = PK11_TokenKeyGenWithFlags(slot, CKM_DES2_KEY_GEN, 0, 0, 0, CKA_ENCRYPT, pk11AttrGenMasterKeyFlags, &pwdata);

                if( masterKey == NULL ) {
                    PR_fprintf( PR_STDERR,
                                "%s -%c:  %s:%d\n",
                                progName,
                                commandToRun,
                                "unable to generate/store this DES2 master key ",
                                PR_GetError() );
                    rv = SECFailure;
                    goto shutdown;
                }

            } else if( MASTER_KEY_LENGTH == ( 3 * DES_LENGTH ) ) {

                masterKey = PK11_TokenKeyGenWithFlags(slot, CKM_DES3_KEY_GEN, 0, 0, 0, CKA_ENCRYPT, pk11AttrGenMasterKeyFlags, &pwdata);

                if( masterKey == NULL ) {
                    PR_fprintf( PR_STDERR,
                                "%s -%c:  %s:%d\n",
                                progName,
                                commandToRun,
                                "unable to generate/store this DES3 master key ",
                                PR_GetError() );
                    rv = SECFailure;
                    goto shutdown;
                }
            } else {
                /* invalid key size */
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s\n\n\n",
                            progName,
                            commandToRun,
                            "MASTER_KEY_LENGTH must be DES2 or DES3 length!" );
                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        default:
            break;
        }


        /*****************************************************************/
        /* Finally, name the master key with the specified name.         */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Naming the master key \"%s\" . . .\n\n",
                    keyname );

        rvMasterKeyname = PK11_SetSymKeyNickname(
                          /* symmetric key */     masterKey,
                          /* nickname      */     keyname );
        if( rvMasterKeyname != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to name the master key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }


        /*********************************************/
        /* Compute and display the master key's KCV. */
        /*********************************************/

        PR_fprintf( PR_STDOUT,
                    "Computing and displaying KCV of the master key "
                    "on the specified token . . .\n\n" );

        /* Calculate the master key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        masterKey,
                                                        keyname,
                                                        RESIDENT_KEY,
                                                        keyAlg,
                                                        PR_TRUE,
                                                        NULL );
        if( rvKCV != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to compute/display KCV of "
                        "the master key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        } else {
            PR_fprintf( PR_STDOUT,
                        "Successfully generated, stored, and named the "
                        "master key\nincluding computing and displaying "
                        "its KCV!\n\n" );
        }


        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


    /**************************************************************/
    /* Execute the "-N" new software database creation command    */
    /*                                                            */
    /* NOTE:  This command is mutually exclusive from all others. */
    /*        Always initialize the password when creating a new  */
    /*        set of software databases                           */
    /**************************************************************/

    if( pistool.commands[cmd_NewDBs].activated ) {
        rv = SECU_ChangePW( slot,
                            0,
                            pwdata.data );
        goto shutdown;
    }


    /****************************************************/
    /* Execute the "-P" change key DB password command  */
    /*                                                  */
    /* NOTE:  This command is mutually exclusive from   */
    /*        all others. (future - change pw to slot?) */
    /****************************************************/

    if(pistool.commands[cmd_ChangePassword].activated ) {
        rv = SECU_ChangePW( slot,
                            0,
                            pwdata.data );
        goto shutdown;
    }


    /***************************************/
    /* Execute the "-R" rename key command */
    /*                                     */
    /* NOTE:  This command is mutually     */
    /*        exclusive from all others.   */
    /***************************************/

    if( pistool.commands[cmd_RenameKey].activated ) {

        /*****************************************************/
        /*  Check that specified keynames are not identical. */
        /*****************************************************/
        if( PL_strcmp( keyname, new_keyname ) == 0 ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe two keynames specified by "
                        "\n\t\t\"-n %s\" and \"-r %s\" are identical."
                        "\n\t\tPlease provide two non-identical keynames.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        new_keyname );
            rv = SECFailure;
            goto shutdown;
        }

        /*****************************************************/
        /* Retrieve a handle to the specified symmetric key. */
        /* This insures that the specified symmetric key     */
        /* already resides on the specified token.           */
        /*****************************************************/

        symmetricKey = TKS_RetrieveSymKey( slot,
                                           keyname,
                                           &pwdata );
        if( symmetricKey == NULL ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" symmetric keyname specified by "
                        "\n\t\t\"-n %s\" does NOT exist on the specified "
                        "token.\n\t\tPlease specify a "
                        "different symmetric keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /**********************************************************/
        /*  Do not allow the renamed key to overwrite a           */
        /*  preexisting key of the same name                      */
        /*                                                        */
        /*  NOTE:  The following code snippet effectively         */
        /*         prohibits this tool from renaming any          */
        /*         symmetric key with a keyname that already      */
        /*         resides in the specified token                 */
        /**********************************************************/

        rvFindSymKey = TKS_FindSymKey( slot,
                                       new_keyname,
                                       &pwdata );
        if( rvFindSymKey == SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" keyname specified by "
                        "\n\t\t\"-r %s\"\n\t\talready exists in the "
                        "specified token.\n\t\tPlease specify a "
                        "different keyname for renaming purposes.\n\n",
                        progName,
                        commandToRun,
                        new_keyname,
                        new_keyname );
            rv = SECFailure;
            goto shutdown;
        }

        /* Detect the key type (AES or DES) */
        KeyAlgorithm detectedAlg = TKS_DetectKeyAlgorithm(symmetricKey);
        if(detectedAlg == KEY_ALG_UNKNOWN)
        {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to detect the algorithm of "
                        "this symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }

        PR_fprintf(PR_STDOUT, "This key is of type: ");
        switch(detectedAlg)
        {
        case KEY_ALG_AES: PR_fprintf(PR_STDOUT, ALG_AES" . . .\n\n"); break;
        case KEY_ALG_DES: PR_fprintf(PR_STDOUT, ALG_DES" . . .\n\n"); break;
        }

#if defined(DEBUG)
        /*****************************************************************/
        /* For convenience, compute and display the symmetric key's KCV. */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Computing and displaying KCV of the symmetric key "
                    "on the specified token . . .\n\n" );

        /* Calculate the symmetric key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        symmetricKey,
                                                        keyname,
                                                        RESIDENT_KEY,
                                                        detectedAlg,
                                                        PR_TRUE,
                                                        NULL );
        if( rvKCV != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to compute/display KCV of "
                        "the symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }
#endif


        /********************************************************************/
        /* Finally, rename the symmetric key with the newly specified name. */
        /********************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Renaming the symmetric key named \"%s\" to \"%s\" . . .\n\n",
                    keyname,
                    new_keyname );

        rvSymmetricKeyname = PK11_SetSymKeyNickname(
                             /* symmetric key */     symmetricKey,
                             /* nickname      */     new_keyname );
        if( rvSymmetricKeyname != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to rename the symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        } else {
            PR_fprintf( PR_STDOUT,
                        "Successfully renamed the symmetric key named \"%s\" "
                        "to \"%s\"!\n\n",
                        keyname,
                        new_keyname );
        }


#if defined(DEBUG)
        /********************************************************/
        /* For convenience, compute and display the renamed     */
        /* symmetric key's KCV.                                 */
        /********************************************************/

        PR_fprintf( PR_STDOUT,
                    "Computing and displaying KCV of the renamed symmetric key "
                    "on the specified token . . .\n\n" );

        /* Calculate the renamed symmetric key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        symmetricKey,
                                                        new_keyname,
                                                        RESIDENT_KEY,
                                                        detectedAlg,
                                                        PR_TRUE,
                                                        NULL );
        if( rvKCV != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to compute/display KCV of "
                        "the renamed symmetric key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }
#endif


        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


    /**************************************************/
    /* Execute the "-S" list security modules command */
    /*                                                */
    /* NOTE:  This command is mutually                */
    /*        exclusive from all others.              */
    /**************************************************/

    if( pistool.commands[cmd_ListSecModules].activated ) {
        rv = TKS_ListSecModules();
        goto shutdown;
    }


    /**********************************************/
    /* Execute the "-U" unwrap master key command */
    /*                                            */
    /* NOTE:  This command is mutually            */
    /*        exclusive from all others.          */
    /**********************************************/

    if( pistool.commands[cmd_UnWrapMasterKey].activated ) {

        /**********************************************************/
        /*  Do not allow duplicate symmetric keys to be stored    */
        /*  (i. e. - disallow symmetric keys specified            */
        /*           by the same keyname)                         */
        /*                                                        */
        /*  NOTE:  The following code snippet effectively         */
        /*         prohibits this tool from storing any           */
        /*         symmetric key with a keyname that already      */
        /*         resides in the specified token                 */
        /**********************************************************/

        rvFindSymKey = TKS_FindSymKey( slot,
                                       keyname,
                                       &pwdata );
        if( rvFindSymKey == SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" keyname specified by "
                        "\n\t\t\"-n %s\"\n\t\talready exists in the "
                        "specified token.\n\t\tPlease specify a "
                        "different keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /*******************************************************************/
        /* Retrieve a handle to the specified unwrapping key. This insures */
        /* that the specified unwrapping key (i. e. - transport key)       */
        /* already exists on the specified token.                          */
        /*                                                                 */
        /* NOTE:  Requiring that the transport key AND the master key      */
        /*        reside on the same token is a FIPS 140-1 requirement!    */
        /*******************************************************************/

        TKS_ClearScreen();

        PR_fprintf( PR_STDOUT,
                    "\nRetrieving the transport key from the "
                    "specified token (for unwrapping) . . .\n\n" );

        transportKey = TKS_RetrieveSymKey( slot,
                                           transport_keyname,
                                           &pwdata );
        if( transportKey == NULL ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" transport keyname specified by "
                        "\"-t %s\"\n\t\tdoes NOT exist on the specified "
                        "token.\n\t\tPlease specify a "
                        "different transport keyname.\n\n",
                        progName,
                        commandToRun,
                        transport_keyname,
                        transport_keyname );
            rv = SECFailure;
            goto shutdown;
        }

        /*
         * Make sure the transport key's mechanism (algorithm) matches the
         * algorithm given on the command line
         */
        KeyAlgorithm detectedAlg = TKS_DetectKeyAlgorithm(transportKey);
        if(detectedAlg == KEY_ALG_UNKNOWN)
        {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to detect the algorithm of "
                        "this transport key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }

        PR_fprintf(PR_STDOUT, "The transport key is of type: ");
        switch(detectedAlg)
        {
        case KEY_ALG_AES: PR_fprintf(PR_STDOUT, ALG_AES" . . .\n\n"); break;
        case KEY_ALG_DES: PR_fprintf(PR_STDOUT, ALG_DES" . . .\n\n"); break;
        }

        /*****************************************************************/
        /* Read in the wrapped master key from the specified input file. */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Reading in the wrapped data (and resident master key KCV) "
                    "from the file called\n\"%s\" . . .\n\n",
                    input );

        /* Create a clean new storage buffer for this wrapped key */
        wrappedMasterKey.len  = WRAPPED_KEY_LENGTH;
        wrappedMasterKey.data = ( unsigned char * )
                                PORT_ZAlloc( WRAPPED_KEY_LENGTH );

        /* Create a clean new hex storage buffer for this master key's KCV */
        hexInternalKeyKCV.type = ( SECItemType ) siBuffer;
        hexInternalKeyKCV.len  = ( HEX_WRAPPED_KEY_KCV_LENGTH + 1 );
        hexInternalKeyKCV.data = ( unsigned char * )
                               PORT_ZAlloc( hexInternalKeyKCV.len );
        if( hexInternalKeyKCV.data == NULL ) {
            rv = SECFailure;
            goto shutdown;
        }

        rvWrappedMasterKey = TKS_ReadInputFileIntoSECItem( input,
                                                           ( char * ) hexInternalKeyKCV.data,
                                                           hexInternalKeyKCV.len,
                                                           keyname,
                                                           &wrappedMasterKey );
        if( rvWrappedMasterKey != SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tunable to read in wrapped master key "
                        "from file called \"%s\".\n",
                        progName,
                        commandToRun,
                        input );
            rv = SECFailure;
            goto shutdown;
        }


        /*************************************************************/
        /* Temporarily unwrap the master key to check its KCV value. */
        /*************************************************************/

        PR_fprintf( PR_STDOUT,
                    "\n\nUsing the transport key to temporarily unwrap "
                    "the master key to recompute\nits KCV value to "
                    "check against its pre-computed KCV value . . .\n\n" );

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            temporaryMasterKey = PK11_UnwrapSymKeyWithFlagsPerm(
                                 /* wrapping key      */         transportKey,
                                 /* wraptype          */         CKM_AES_ECB,
                                 /* param             */         0,
                                 /* wrapped key       */         &wrappedMasterKey,
                                 /* target            */         CKM_AES_CBC,
                                 /* operation         */         CKA_ENCRYPT,
                                 /* target key length */         WRAPPED_KEY_LENGTH,
                                 /* flags             */         0,
                                 /* isPerm            */         PR_FALSE );
            break;
        }
        case KEY_ALG_DES:
        {
            temporaryMasterKey = PK11_UnwrapSymKeyWithFlagsPerm(
                                 /* wrapping key      */         transportKey,
                                 /* wraptype          */         CKM_DES3_ECB,
                                 /* param             */         0,
                                 /* wrapped key       */         &wrappedMasterKey,
                                 /* target            */         CKM_DES3_ECB,
                                 /* operation         */         CKA_ENCRYPT,
                                 /* target key length */         WRAPPED_KEY_LENGTH,
                                 /* flags             */         0,
                                 /* isPerm            */         PR_FALSE );
            break;
        }
        default:
            break;
        }

        if( temporaryMasterKey == NULL ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to temporarily unwrap the master key ",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }

        /* verify that the wrapped key and KCV read in from   */
        /* the input file correspond to each other . . .      */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                          temporaryMasterKey,
                                          keyname,
                                          UNWRAPPED_KEY,
                                          keyAlg,
                                          PR_FALSE,
                                          hexInternalKeyKCV.data );
        if( rvKCV != SECSuccess ) {
            rv = SECFailure;
            goto shutdown;
        }


        /***************************************************************/
        /* Unwrap the master key and store it on the designated token. */
        /***************************************************************/

        PR_fprintf( PR_STDOUT,
                    "\nUsing the transport key to unwrap and store "
                    "the master key\non the specified token . . .\n\n" );

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            masterKey = PK11_UnwrapSymKeyWithFlagsPerm(
                        /* wrapping key      */         transportKey,
                        /* wraptype          */         CKM_AES_ECB,
                        /* param             */         0,
                        /* wrapped key       */         &wrappedMasterKey,
                        /* target            */         CKM_AES_CBC,
                        /* operation         */         CKA_ENCRYPT,
                        /* target key length */         WRAPPED_KEY_LENGTH,
                        /* flags             */         0,
                        /* isPerm            */         PR_TRUE );
            break;
        }
        case KEY_ALG_DES:
        {
            masterKey = PK11_UnwrapSymKeyWithFlagsPerm(
                        /* wrapping key      */         transportKey,
                        /* wraptype          */         CKM_DES3_ECB,
                        /* param             */         0,
                        /* wrapped key       */         &wrappedMasterKey,
                        /* target            */         CKM_DES3_ECB,
                        /* operation         */         CKA_ENCRYPT,
                        /* target key length */         WRAPPED_KEY_LENGTH,
                        /* flags             */         0,
                        /* isPerm            */         PR_TRUE );
            break;
        }
        default:
            break;
        }

        if( masterKey == NULL ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to unwrap/store the master key ",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }


        //PAS MOD FE4
        //This code flips the CKA_Extractible bit from true to false.
        SECItem seciCKAExtractable;
        CK_BBOOL f = CK_FALSE;

        seciCKAExtractable.data = (unsigned char *)PR_Malloc(sizeof(CK_BBOOL));

        PORT_Memcpy(seciCKAExtractable.data, (void *)&f, sizeof(CK_BBOOL));


        seciCKAExtractable.len = sizeof(CK_BBOOL);

        rvMasterKeyname = PK11_WriteRawAttribute(PK11_TypeSymKey, (void *)masterKey, CKA_EXTRACTABLE, &seciCKAExtractable);

        if( rvMasterKeyname != SECSuccess ){
        	PR_fprintf(PR_STDERR, "WARNING: Setting the CKA_EXTRACTIBLE attribute for the master key to false failed!\n");

            if( PORT_GetError() == SEC_ERROR_READ_ONLY ){
            	PR_fprintf(PR_STDERR, "CKA_EXTRACTIBLE is readonly!\n");
            }

        }

        if(seciCKAExtractable.data != NULL){
        	PR_Free(seciCKAExtractable.data);
        	seciCKAExtractable.data = NULL;
        }



        /*****************************************************************/
        /* Finally, name the master key with the specified name.         */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                "Naming the master key \"%s\" . . .\n\n",
                keyname );

        rvMasterKeyname = PK11_SetSymKeyNickname( 
                          /* symmetric key */     masterKey,
                          /* nickname      */     keyname );
        if( rvMasterKeyname != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to name the master key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        } else {
            PR_fprintf( PR_STDOUT,
                        "Successfully unwrapped, stored, and named the "
                        "master key!\n\n" );
        }


        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


    /******************************************************/
    /* Execute the "-W" wrap generated master key command */
    /*                                                    */
    /* NOTE:  This command is mutually                    */
    /*        exclusive from all others.                  */
    /******************************************************/

    if( pistool.commands[cmd_WrapMasterKey].activated ) {

        /**********************************************************/
        /*  Do not allow duplicate symmetric keys to be stored    */
        /*  (i. e. - disallow symmetric keys specified            */
        /*           by the same keyname)                         */
        /*                                                        */
        /*  NOTE:  The following code snippet effectively         */
        /*         prohibits this tool from storing any           */
        /*         symmetric key with a keyname that already      */
        /*         resides in the specified token                 */
        /**********************************************************/

        rvFindSymKey = TKS_FindSymKey( slot,
                                       keyname,
                                       &pwdata );
        if( rvFindSymKey == SECSuccess ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" keyname specified by "
                        "\n\t\t\"-n %s\"\n\t\talready exists in the "
                        "specified token.\n\t\tPlease specify a "
                        "different keyname.\n\n",
                        progName,
                        commandToRun,
                        keyname,
                        keyname );
            rv = SECFailure;
            goto shutdown;
        }


        /*****************************************************************/
        /* Retrieve a handle to the specified wrapping key. This insures */
        /* that the specified wrapping key (i. e. - transport key)       */
        /* already exists on the specified token.                        */
        /*                                                               */
        /* NOTE:  Requiring that the transport key AND the master key    */
        /*        reside on the same token is a FIPS 140-1 requirement!  */
        /*****************************************************************/

        TKS_ClearScreen();

        PR_fprintf( PR_STDOUT,
                    "\nRetrieving the transport key (for wrapping) "
                    "from the specified token . . .\n\n" );

        transportKey = TKS_RetrieveSymKey( slot,
                                           transport_keyname,
                                           &pwdata );
        if( transportKey == NULL ) {
            PR_fprintf( PR_STDERR, 
                        "%s -%c:\tthe \"%s\" transport keyname specified by "
                        "\"-t %s\"\n\t\tdoes NOT exist on the specified "
                        "token.\n\t\tPlease specify a "
                        "different transport keyname.\n\n",
                        progName,
                        commandToRun,
                        transport_keyname,
                        transport_keyname );
            rv = SECFailure;
            goto shutdown;
        }

        /*
         * The transport key type and the requested master key type
         * must match.
         */
        KeyAlgorithm detectedAlg = TKS_DetectKeyAlgorithm(transportKey);
        if(detectedAlg == KEY_ALG_UNKNOWN)
        {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Unable to detect the algorithm of "
                        "this transport key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        }
        else if(detectedAlg != keyAlg)
        {
            char *detectedAlgString;
            switch(detectedAlg)
            {
            case KEY_ALG_AES: detectedAlgString = ALG_AES; break;
            case KEY_ALG_DES: detectedAlgString = ALG_DES; break;
            }

            PR_fprintf(PR_STDERR,
                    "The transport key type (%s) does not match the -a algorithm"
                    " parameter. Exiting.\n\n", detectedAlgString);

            rv = SECFailure;
            goto shutdown;
        }

        /*****************************************************************/
        /* Generate the master key and store it on the designated token. */
        /*****************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Generating and storing the master key "
                    "on the specified token . . .\n\n" );

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            masterKey = PK11_TokenKeyGenWithFlags(
                    slot,
                    CKM_AES_KEY_GEN,
                    0,
                    AES_128_LENGTH_BYTES,
                    0,
                    CKA_ENCRYPT,
                    pk11AttrGenMasterKeyFlags,
                    &pwdata);

            if(masterKey == NULL)
            {
                PR_fprintf(PR_STDERR,
                        "%s -%c: %s:%d\n\n\n",
                        progName,
                        commandToRun,
                        "Unable to generate/store this AES master key",
                        PR_GetError());

                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        case KEY_ALG_DES:
        {
            if( WRAPPED_KEY_LENGTH == ( 2 * DES_LENGTH ) ) {
                masterKey = PK11_TokenKeyGen(
                /* slot                     */  slot,
                /* mechanism                */  CKM_DES2_KEY_GEN,
                /* param                    */  0,
                /* keySize                  */  0,
                /* keyid                    */  0,
                /* isToken (i. e. - isPerm) */  PR_TRUE,
                /* wincx                    */  &pwdata );
                if( masterKey == NULL ) {
                    PR_fprintf( PR_STDERR,
                                "%s -%c:  %s:%d\n",
                                progName,
                                commandToRun,
                                "unable to generate/store this DES2 master key ",
                                PR_GetError() );
                    rv = SECFailure;
                    goto shutdown;
                }
            } else if( WRAPPED_KEY_LENGTH == ( 3 * DES_LENGTH ) ) {
                masterKey = PK11_TokenKeyGen(
                /* slot                     */  slot,
                /* mechanism                */  CKM_DES3_KEY_GEN,
                /* param                    */  0,
                /* keySize                  */  0,
                /* keyid                    */  0,
                /* isToken (i. e. - isPerm) */  PR_TRUE,
                /* wincx                    */  &pwdata );
                if( masterKey == NULL ) {
                    PR_fprintf( PR_STDERR,
                                "%s -%c:  %s:%d\n",
                                progName,
                                commandToRun,
                                "unable to generate/store this DES3 master key ",
                                PR_GetError() );
                    rv = SECFailure;
                    goto shutdown;
                }
            } else {
                /* invalid key size */
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s\n\n\n",
                            progName,
                            commandToRun,
                            "WRAPPED_KEY_LENGTH must be DES2 or DES3 length!" );
                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        default:
            break;
        }


        /************************************************/
        /* Name the master key with the specified name. */
        /************************************************/

        PR_fprintf( PR_STDOUT,
                "Naming the master key \"%s\" . . .\n\n",
                keyname );

        rvMasterKeyname = PK11_SetSymKeyNickname( 
                          /* symmetric key */     masterKey,
                          /* nickname      */     keyname );
        if( rvMasterKeyname != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to name the master key!\n\n" );
            rv = SECFailure;
            goto shutdown;
        } else {
            PR_fprintf( PR_STDOUT,
                        "Successfully generated, stored, and named the "
                        "master key!\n\n" );
        }


        /**********************************/
        /* Compute this master key's KCV. */
        /**********************************/

        /* Create a clean new hex storage buffer for this master key's KCV */
        hexInternalKeyKCV.type = ( SECItemType ) siBuffer;
        hexInternalKeyKCV.len  = ( HEX_WRAPPED_KEY_KCV_LENGTH + 1 );
        hexInternalKeyKCV.data = ( unsigned char * )
                               PORT_ZAlloc( hexInternalKeyKCV.len );
        if( hexInternalKeyKCV.data == NULL ) {
            rv = SECFailure;
            goto shutdown;
        }

        /* Calculate this master key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) NULL,
                                          ( PRIntn )    0,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        masterKey,
                                                        keyname,
                                                        WRAPPED_KEY,
                                                        keyAlg,
                                                        PR_FALSE,
                                                        hexInternalKeyKCV.data );
        if( rvKCV != SECSuccess ) {
            rv = SECFailure;
            goto shutdown;
        }


        /****************************************/
        /* Wrap the newly generated master key. */
        /****************************************/

        PR_fprintf( PR_STDOUT,
                    "Using the transport key to wrap and store "
                    "the master key . . .\n\n" );

        wrappedMasterKey.len  = WRAPPED_KEY_LENGTH;
        wrappedMasterKey.data = ( unsigned char * )
                                PORT_ZAlloc( WRAPPED_KEY_LENGTH );

        switch(keyAlg)
        {
        case KEY_ALG_AES:
        {
            rvWrappedMasterKey = PK11_WrapSymKey(
                    CKM_AES_ECB,
                    0,
                    transportKey,
                    masterKey,
                    &wrappedMasterKey);
            if( rvWrappedMasterKey != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s:%d\n",
                            progName,
                            commandToRun,
                            "unable to wrap the master key ",
                            PR_GetError() );
                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        case KEY_ALG_DES:
        {
            rvWrappedMasterKey = PK11_WrapSymKey(
            /* mechanism type    */               CKM_DES3_ECB,
            /* param             */               0,
            /* wrapping key      */               transportKey,
            /* key to be wrapped */               masterKey,
            /* wrapped key       */               &wrappedMasterKey );
            if( rvWrappedMasterKey != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "%s -%c:  %s:%d\n",
                            progName,
                            commandToRun,
                            "unable to wrap the master key ",
                            PR_GetError() );
                rv = SECFailure;
                goto shutdown;
            }

            break;
        }
        default:
            break;
        }


        /**************************************************************/
        /* Write the wrapped master key to the specified output file. */
        /**************************************************************/

        PR_fprintf( PR_STDOUT,
                    "Writing the wrapped data (and resident master key KCV) "
                    "into the file called\n\"%s\" . . .\n\n",
                    output );

        rvSaveWrappedMasterKey = TKS_WriteSECItemIntoOutputFile( &wrappedMasterKey,
                                                                 keyname,
                                                                 ( char * ) hexInternalKeyKCV.data,
                                                                 ( hexInternalKeyKCV.len - 1 ),
                                                                 output );
        if( rvSaveWrappedMasterKey != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "%s -%c:  %s:%d\n",
                        progName,
                        commandToRun,
                        "unable to save the wrapped master key ",
                        PR_GetError() );
            rv = SECFailure;
            goto shutdown;
        }


        //PAS MOD FE4
        //This code flips the CKA_Extractible bit from true to false.
        SECItem seciCKAExtractable;
        CK_BBOOL f = CK_FALSE;
        seciCKAExtractable.data = (unsigned char *)PR_Malloc(sizeof(CK_BBOOL));

        PORT_Memcpy(seciCKAExtractable.data, (void *)&f, sizeof(CK_BBOOL));

        seciCKAExtractable.len = sizeof(CK_BBOOL);

        rvMasterKeyname = PK11_WriteRawAttribute(PK11_TypeSymKey, (void *)masterKey, CKA_EXTRACTABLE, &seciCKAExtractable);

        if( rvMasterKeyname != SECSuccess ){
        	PR_fprintf(PR_STDERR, "WARNING: Setting the CKA_EXTRACTIBLE attribute for the master key to false failed!\n");

            if( PORT_GetError() == SEC_ERROR_READ_ONLY ){
            	PR_fprintf(PR_STDERR, "CKA_EXTRACTIBLE is readonly!\n");
            }

        }

        if(seciCKAExtractable.data != NULL){
        	PR_Free(seciCKAExtractable.data);
        	seciCKAExtractable.data = NULL;
        }




        /*********************************/
        /* Cleanup and exit with success */
        /*********************************/

        rv = SECSuccess;
        goto shutdown;
    }


shutdown:
    /* free internal slot */
    if( slot ) {
        PK11_FreeSlot( /* slot */  internalSlot );
    }


    /* free slot */
    if( slot ) {
        PK11_FreeSlot( /* slot */  slot );
    }


    /* destroy the pwdata */
    if( pwdata.data != NULL ) {
        pwdata.source = PW_NONE;
        i = 0;
        do {
           if( pwdata.data[i] != 0 ) {
               pwdata.data[i] = 0;
               i++;
           } else {
               status = PR_TRUE;
           }
        } while( status == PR_FALSE );
    }


    /* destroy the first session key share */
    if( firstSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    firstSessionKeyShare.data,
                    firstSessionKeyShare.len );
        firstSessionKeyShare.data = NULL;
        firstSessionKeyShare.len  = 0;
    }


#if defined(PAD_DES2_KEY_LENGTH)
    /* destroy the first padded session key share */
    if( paddedFirstSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    paddedFirstSessionKeyShare.data,
                    paddedFirstSessionKeyShare.len );
        paddedFirstSessionKeyShare.data = NULL;
        paddedFirstSessionKeyShare.len  = 0;
    }
#endif


    /* destroy the "original" second session key share */
    if( secondDerivationData.pData != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    secondDerivationData.pData,
                    secondDerivationData.ulLen );
        secondDerivationData.pData = NULL;
        secondDerivationData.ulLen = 0;
    }


#if defined(PAD_DES2_KEY_LENGTH)
    /* destroy the second padded session key share */
    if( paddedSecondSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    paddedSecondSessionKeyShare.data,
                    paddedSecondSessionKeyShare.len );
        paddedSecondSessionKeyShare.data = NULL;
        paddedSecondSessionKeyShare.len  = 0;
    }
#endif


    /* destroy the second session key share container */
    if( secondSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    secondSessionKeyShare.data,
                    secondSessionKeyShare.len );
        secondSessionKeyShare.data = NULL;
        secondSessionKeyShare.len  = 0;
    }


    /* destroy the "original" third session key share */
    if( thirdDerivationData.pData != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    thirdDerivationData.pData,
                    thirdDerivationData.ulLen );
        thirdDerivationData.pData = NULL;
        thirdDerivationData.ulLen = 0;
    }


#if defined(PAD_DES2_KEY_LENGTH)
    /* destroy the third padded session key share */
    if( paddedThirdSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    paddedThirdSessionKeyShare.data,
                    paddedThirdSessionKeyShare.len );
        paddedThirdSessionKeyShare.data = NULL;
        paddedThirdSessionKeyShare.len  = 0;
    }
#endif


    /* destroy the third session key share container */
    if( thirdSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    thirdSessionKeyShare.data,
                    thirdSessionKeyShare.len );
        thirdSessionKeyShare.data = NULL;
        thirdSessionKeyShare.len  = 0;
    }


    /* destroy the first symmetric key */
    if( firstSymmetricKey ) {
        PK11_FreeSymKey( /* symmetric key */  firstSymmetricKey );
    }


    /* destroy the second symmetric key */
    if( secondSymmetricKey ) {
        PK11_FreeSymKey( /* symmetric key */  secondSymmetricKey );
    }


    /* destroy the third symmetric key (transport key) */
    if( thirdSymmetricKey ) {
        PK11_FreeSymKey( /* symmetric key */  thirdSymmetricKey );
    }


    /* destroy the hexInternalKeyKCV */
    if( hexInternalKeyKCV.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexInternalKeyKCV.data,
                    hexInternalKeyKCV.len );
        hexInternalKeyKCV.data = NULL;
        hexInternalKeyKCV.len  = 0;
    }


    /* destroy the KCV */
    if( KCV != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    KCV,
                    KCVLen );
        KCV = NULL;
        KCVLen = 0;
    }


    /* destroy the temporary master key */
    if( temporaryMasterKey ) {
        PK11_FreeSymKey( /* symmetric key */  temporaryMasterKey );
    }


    /* destroy the master key */
    if( masterKey ) {
        PK11_FreeSymKey( /* symmetric key */  masterKey );
    }


    /* destroy the transport key */
    if( transportKey ) {
        PK11_FreeSymKey( /* symmetric key */  transportKey );
    }


    /* shutdown NSS */
    if( NSS_Shutdown() != SECSuccess ) {
        return 255;
    }


    /* exit with an appropriate return value */
    if( rv == SECSuccess ) {
        return 0;
    } else {
        return 255;
    }
}

