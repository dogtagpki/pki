Install
=======

* pkilib is a python library which contains shared functions to be used with py.test  to automate CLI, Web UI of Red Hat Certificate Services and 
  Dogtag PKI.

Dependencies
------------
    pkilib requires following packages:

        1. python-paramiko
        2. python-pytest-multihost
        3. PyYAML
        4. python-ldap
        5. pytest
        6. ipa-python(freeipa-ipapython)
        7. python-dns
        8. python-krbV
RHEL7.2
-------
* pkilib can be downloaded from `this link <https://mrniranjan.fedorapeople.org/pkilib-0.1-1.el7.noarch.rpm>`_.
To install above dependencies on RHEL7.2 get the `idmqe-extras-repo <http://cosmos.lab.eng.pnq.redhat.com/idmqe-extras>`_.file::

    wget -O /etc/yum.repos.d/idmqe-extras-rhel.repo \
    http://cosmos.lab.eng.pnq.redhat.com/idmqe-extras/idmqe-extras-rhel.repo
   

Fedora 21
---------
* On fedora 21, all the dependencies are provided on Base Fedora repository. Download the pkilib rpm from `here <https://mrniranjan.fedorapeople.org/pkilib-0.1-1.fc21.noarch.rpm>`_.::

   wget https://mrniranjan.fedorapeople.org/pkilib-0.1-1.fc21.noarch.rpm/pki_tests-0.1.noarch.f21.rpm
   yum localinstall pki_tests-0.1.noarch.f21.rpm
