#!/bin/sh
if [ $# -lt 2 ] ; then
    echo "Terminateing"
    cat << __EOF__

        Usage: ./setupssl.sh <[options]>
        Options:
                -d      Directory Server
                -p      Unsecure port
                -t      TLS Secure port
                -pass   LDAP database password

__EOF__
    exit 1
fi
ldapport=389
ldapsport=636
lpass="Secret123"

while true
do
    case "$1" in 
        -d )
            shift
            if [ "$1" -a -d "$1" ] ; then
                secdir="$1"
                echo "Using $1 as sec directory"
                assecdir=$secdir/
            fi
        ;;

        -p ) 
            shift
            if [ "$1" ] ; then
                ldapport=$1
            fi
        ;;
        -t )
            shift
            if [ "$1" ] ; then
                ldapsport=$1
            fi
        ;;

        -pass )
            shift
            if [ "$1" ] ; then
                lpass=$1
            fi
        ;;

        * ) 
            break
        ;;
    esac
    shift
done


me=`whoami`
if [ "$me" = "root" ] ; then
    isroot=1
fi
#check secure port is peresent or not

if lsof -i:$ldapsport
then
    echo $ldapsport" is not free. Specify another port."
    echo " Exiting"
    exit 1
else
    echo "$ldapsport is free to use."
fi

needCA=1
needServerCert=1
needASCert=1
prefix="new-"
prefixarg="-P $prefix"

if test -z "$needCA" -a -z "$needServerCert" -a -z "$needASCert" ; then
    echo "No certs needed - exiting"
    exit 0
fi

# get our user and group
if test -n "$isroot" ; then
    uid=`/bin/ls -ald $secdir | awk '{print $3}'`
    gid=`/bin/ls -ald $secdir | awk '{print $4}'`
fi

# 2. Create a password file for your security token password:
if [ -f $secdir/pwdfile.txt ] ; then
    echo "Using existing $secdir/pwdfile.txt"
else
    echo "Creating password file for security token"
    (ps -ef ; w ) | sha1sum | awk '{print $1}' > $secdir/pwdfile.txt
    if test -n "$isroot" ; then
        chown $uid:$gid $secdir/pwdfile.txt
    fi
        chmod 400 $secdir/pwdfile.txt
fi

# 3. Create a "noise" file for your encryption mechanism:
if [ -f $secdir/noise.txt ] ; then
    echo "Using existing $secdir/noise.txt file"
else
    echo "Creating noise file"
    (w ; ps -ef ; date ) | sha1sum | awk '{print $1}' > $secdir/noise.txt
    if test -n "$isroot" ; then
        chown $uid:$gid $secdir/noise.txt
    fi
    chmod 400 $secdir/noise.txt
fi

# 4. Create the key4.db and cert9.db databases:
if [ -z "$prefix" ] ; then
    echo "Creating initial key and cert db"
else
    echo "Creating new key and cert db"
fi
certutil -N $prefixarg -d $secdir -f $secdir/pwdfile.txt
if test -n "$isroot" ; then
    chown $uid:$gid $secdir/${prefix}key4.db $secdir/${prefix}cert9.db
fi
chmod 600 $secdir/${prefix}key4.db $secdir/${prefix}cert9.db

CAserialNo=1000
ServerCertSerialNo=1001
ServerAdminServerCertNo=1002

if test -n "$needCA" ; then
# 5. Generate the encryption key:
    echo "Creating encryption key for CA"
    certutil -G $prefixarg -d $secdir -z $secdir/noise.txt -f $secdir/pwdfile.txt
# 6. Generate the self-signed certificate:
    echo "Creating self-signed CA certificate"
    echo "CA Certificate Serial No [1] :"
    if [ ! -z $certNo -a $certNo!="" ]; then
	   CAserialNo=$certNo
    fi
# note - the basic constraints flag (-2) is required to generate a real CA cert
# it asks 3 questions that cannot be supplied on the command line
    ( echo y ; echo ; echo y ) | certutil -S $prefixarg -n "CA certificate" -s "cn=CAcert" -x -t "CT,," -m $CAserialNo -v 120 -d $secdir -z $secdir/noise.txt -f $secdir/pwdfile.txt -2
# export the CA cert for use with other apps
    echo Exporting the CA certificate to cacert.asc
    certutil -L $prefixarg -d $secdir -n "CA certificate" -a > $secdir/cacert.asc
fi

if test -n "$MYHOST" ; then
    myhost="$MYHOST"
else
    myhost=`hostname --fqdn`
fi
if test -n "$needServerCert" ; then
# 7. Generate the server certificate:
    echo "Generating server certificate for 389 Directory Server on host $myhost"
    echo Using fully qualified hostname $myhost for the server name in the server cert subject DN
    echo Note: If you do not want to use this hostname, edit this script to change myhost to the
    echo real hostname you want to use
    echo "Server-Cert Certificate Serial No [2]:"
    if [ ! -z $serverCert -a $serverCert!="" ]; then
	    ServerCertSerialNo=$serverCert
    fi
    certutil -S $prefixarg -n "Server-Cert" -s "cn=$myhost,ou=389 Directory Server" -c "CA certificate" -t "u,u,u" -m $ServerCertSerialNo -v 120 -d $secdir -z $secdir/noise.txt -f $secdir/pwdfile.txt
fi

if test -n "$needASCert" ; then
# Generate the admin server certificate
    echo Creating the admin server certificate
    echo "Admin Server Certificate Serial No [3]:"

    if [ ! -z $admincert -a $admincert!="" ]; then
	    ServerAdminServerCertNo=$admincert
    fi
    certutil -S $prefixarg -n "server-cert" -s "cn=$myhost,ou=389 Administration Server" -c "CA certificate" -t "u,u,u" -m $ServerAdminServerCertNo -v 120 -d $secdir -z $secdir/noise.txt -f $secdir/pwdfile.txt

# export the admin server certificate/private key for import into its key/cert db
    echo Exporting the admin server certificate pk12 file
    pk12util -d $secdir $prefixarg -o $secdir/adminserver.p12 -n server-cert -w $secdir/pwdfile.txt -k $secdir/pwdfile.txt
    if test -n "$isroot" ; then
        chown $uid:$gid $secdir/adminserver.p12
    fi
chmod 400 $secdir/adminserver.p12
fi

# create the pin file
if [ ! -f $secdir/pin.txt ] ; then
    echo Creating pin file for directory server
    pinfile=$secdir/pin.txt
    echo 'Internal (Software) Token:'`cat $secdir/pwdfile.txt` > $pinfile
    if test -n "$isroot" ; then
        chown $uid:$gid $pinfile
    fi
    chmod 400 $pinfile
else
    echo Using existing $secdir/pin.txt
fi

if [ -n "$prefix" ] ; then
    # move the old files out of the way
    mv $secdir/cert9.db $secdir/orig-cert9.db
    mv $secdir/key4.db $secdir/orig-key4.db
    # move in the new files - will be used after server restart
    mv $secdir/${prefix}cert9.db $secdir/cert9.db
    mv $secdir/${prefix}key4.db $secdir/key4.db
fi

# create the admin server key/cert db
if [ ! -f $assecdir/cert9.db ] ; then
    echo Creating key and cert db for admin server
    certutil -N -d $assecdir -f $secdir/pwdfile.txt
    if test -n "$isroot" ; then
        chown $uid:$gid $assecdir/*.db
    fi
    chmod 600 $assecdir/*.db
fi

if test -n "$needASCert" ; then
# import the admin server key/cert
    echo "Importing the admin server key and cert (created above)"
    pk12util -d $assecdir -n server-cert -i $secdir/adminserver.p12 -w $secdir/pwdfile.txt -k $secdir/pwdfile.txt

# import the CA cert to the admin server cert db
    echo Importing the CA certificate from cacert.asc
    certutil -A -d $assecdir -n "CA certificate" -t "CT,," -a -i $secdir/cacert.asc -f $secdir/pwdfile.txt
fi

if [ ! -f $assecdir/password.conf ] ; then
# create the admin server password file
    echo Creating the admin server password file
    echo 'internal:'`cat $secdir/pwdfile.txt` > $assecdir/password.conf
    if test -n "$isroot" ; then
        chown $uid:$gid $assecdir/password.conf
    fi
    chmod 400 $assecdir/password.conf
fi

# tell admin server to use the password file
if [ -f $assecdir/nss.conf ] ; then
    cd $assecdir
    echo Enabling the use of a password file in admin server
    sed -e "s@^NSSPassPhraseDialog .*@NSSPassPhraseDialog file:`pwd`/password.conf@" nss.conf > /tmp/nss.conf && mv /tmp/nss.conf nss.conf
    if test -n "$isroot" ; then
        chown $uid:$gid nss.conf
    fi
chmod 400 nss.conf
    cd $secdir
fi

echo "Done. You must restart the directory server and the admin server for the changes to take effect."

