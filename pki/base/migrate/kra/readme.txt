Date

  Tue Oct 17 16:11:07 PDT 2006

Version

  CMS 6.1

Overview

  In CMS6.1 Data Recovery Manager (DRM), it has deployed a 
  complicated key splitting scheme where software token and 
  hardware token are treated differently.

  Both software and hardware token requires a group of N recovery agents
  to be present during the configuration. A Pin is randomly generated
  and splitted into N pieces called shares. Each share is encrypted with
  a password provided by the individual recovery agent. This is to 
  ensure no single recovery agent to access the pin.

  For software token, during configuration, a storage key pair is
  generated, and the private key portion is then encrypted by the 
  Pin mentioned above. The encrypted key is stored in a file called
  kra-key.db in the conf directory. The configuration deletes 
  the private key from the software token. For each recovery 
  operation, the private key is then reconstructed and imported 
  into the software token.

  For hardware token, during configuration, a storage key pair is
  generated on the selected token, then the configuration changes the
  hardware token's pin to the randomly generated pin mentioned above.
  For each recovery operation, the token's pin is reconstructed and
  private key is accessed.

  To provide migration on the user keys that were encrypted with the
  storage keys of CS6.1, we need to be able to migrate the public and
  private keys to the new system. To access the private key, we need
  to have a way to reconstruct the pin.

  This support package provides 2 utilities that can assist the
  migration.

Programs

  RecoverPin - This command is to reconstruct the pin. It reads
               the shares from conf/kra-mn.conf, and prompts for
               agent passwords. It then reconstructs and prints the
               pin to the screen.

  RecoverKey - For software token deployment, the encrypted private 
               key is stored in the file conf/kra-key.db. To recover
               the private key, the user needs to use the pin obtained
               from RecoverPin. Once the private key is recovered into
               the security database. The user can use pk12util to 
               migrate key to the new installation. For hardware token 
               deployment, this command is not necessary.

Examples

  Here is an example of RecoverPin usage

  java -classpath <server-root>/bin/cert/jars/cmscore.jar:<server-root>/bin/cert/jars/nsutil.jar:<server-root>/bin/cert/jars/jss3.jar:.  RecoverPin <path to alias directory> <prefix> <password> <key splitting scheme file>

  For example,

  java -classpath /home/user/cs61/servers/bin/cert/jars/cmscore.jar:/export/home/user/cs61/servers/bin/cert/jars/nsutil.jar:/export/home/user/cs61/servers/bin/cert/jars/jss3.jar:.  RecoverPin /export/home/user/cs61/servers/alias "cert-drm-sunburst-" netscape /export/home/user/cs61/servers/cert-drm/config/kra-mn.conf 

  The output is:

  Got uid 'agent1'
  Got share 'A23UO/q9f40='
  Got encrypted share length '8'
  Please input password for agent1:
  netscape1
  Got password 'netscape1'
  Got decrypted share length '2'
  Got share[0] '0'
  Got share[1] '0'
  Got uid 'agent2'
  Got share 'R+zGVd5zczI='
  Got encrypted share length '8'
  Please input password for agent2:
  netscape2
  Got password 'netscape2'
  Got decrypted share length '2'
  Got share[0] '0'
  Got share[1] '0'
  Got uid 'agent3'
  Got share 'lsipE7cM8jg='
  Got encrypted share length '8'
  Please input password for agent3:
  netscape3
  Got password 'netscape3'
  Got decrypted share length '2'
  Got share[0] '0'
  Got share[1] '0'
  Share size '3'
  Add share 3
  Add share 2
  Add share 1
  => Pin is ''

  Here is an example of RecoverKey usage

  java -classpath <server-root>/bin/cert/jars/cmscore.jar:<server-root>/bin/cert/jars/nsutil.jar:<server-root>/bin/cert/jars/jss3.jar:.  RecoverKey <alias path> <prefix> <db password> <pin from RecoverPin> <nickname> <key db path>

  For example,

  java -classpath /export/home/user/cs61/servers/bin/cert/jars/cmscore.jar:/export/home/user/cs61/servers/bin/cert/jars/nsutil.jar:/export/home/user/cs61/servers/bin/cert/jars/jss3.jar:.  RecoverKey /export/home/user/cs61/servers/alias cert-drm-sunburst- "netscape" "" "kraStorageCert 1161121005622" /export/home/user/cs61/servers/cert-drm/config/kra-key.db

  The output is:

  => Private is 'org.mozilla.jss.pkcs11.PK11RSAPrivateKey@1ab8f9e'

To make the private and public key exportable via pk12util. You need to first
backup the storage certificate, delete it, and then import it 
again. For example,

  certutil -d . -P cert-drm-sunburst- \
                -n "kraStorageCert 1161121005622" -a > storageCert.txt

  certutil -d . -P cert-drm-sunburst- -D -n "kraStorageCert 1161121005622"

  certutil -d . -P cert-drm-sunburst- -A -t "u,u,u" \
                -n "kraStorageCert 1161121005622" -i storageCert.txt

Finally, you can export the private and public key using pk12util

  pk12util -o storage.p12 -d . -P cert-drm-sunburst- \
           -n "kraStorageCert 1161121005622"
