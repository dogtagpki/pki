#!/usr/bin/python
import ldap
import ldap.modlist as modlist
import time

def setup_ldbm(host='localhost', port=389, binddn="CN=Directory Manager", bindpw="Secret123", ldapentry=None, ldapdn=None):
    l = ldap.open('localhost', 389)
    try:
        l.bind(binddn, bindpw)
    except ldap.SERVER_DOWN, e:
        print("ldap server is down")
        return False
    else:
        print("Bind Successful")

    entry=ldapentry
    dn = ldapdn
    ldif = modlist.addModlist(entry)
    print("ldif = ",ldif)
    try:
        l.add_s(dn, ldif)
    except:
        raise
    else:
        print("%s succesfully added" % (dn))
        return True
    finally:
        l.unbind()
        del l

DBName = "%(pki_instance_name)s" % {'pki_instance_name' : 'Example1'}
RootDC = "o=%s" % DBName
RootDCMapping = "%s,cn=mapping tree,cn=config" % RootDC

entry1 = {
        'objectClass' : ['extensibleObject', 'nsBackendInstance'],
        'nsslapd-suffix' : [RootDC]
        }
dn1 = 'cn=%s,cn=ldbm database,cn=plugins,cn=config' % DBName

entry2 = {
        'objectClass':['top', 'extensibleObject','nsMappingTree'],
        'nsslapd-state' : 'backend',
        'nsslapd-backend' : DBName,
        'cn' : RootDC
        }
dn2 = RootDCMapping
setup_ldbm(ldapentry=entry1,ldapdn=dn1)
time.sleep(30)
setup_ldbm(ldapentry=entry2,ldapdn=dn2)

entry3 = {
        'objectClass': ['top', 'dcObject', 'organization'],
        'dc' : [DBName],
        'o' : ['Example,Inc']
        }
dn3 = RootDC
setup_ldbm(ldapentry=entry3,ldapdn=dn3)

