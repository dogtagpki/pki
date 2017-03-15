FROM fedora
MAINTAINER https://github.com/amolkahat

ENV HOME /root
WORKDIR /root
COPY ./pki /root/pki/
RUN cd /root/pki/
RUN dnf -y install git make gcc-c++ python-nose wget rpm-build python-nose python-pytest python-pytest-cov python-tox ansible
RUN dnf builddep -y /root/pki/specs/pki-core.spec ; dnf builddep -y /root/pki/scripts/compose_pki_core_packages rpms ;
RUN dnf -y install /root/packages/RPMS/noarch/* /root/packages/RPMS/x86_64/*; cd ;
RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python get-pip.py
RUN pip install mock pytest pytest-cov pytest-multihost codecov coverall
RUN nosetests --with-coverage --cover-package=/root/pki/tests/python/ /root/pki/tests/python
#RUN cd ~; cd pki/tests/ci/ansible; pwd;  ansible-playbook -i host main.yml --extra-vars "topology=topology-02"
#RUN pkidaemon status
