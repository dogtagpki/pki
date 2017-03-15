# Installing CA, KRA, OCSP, TKS and TPS instances in containers.

# Allocate ip address to the containers.
#cd /root/dogtag/
cd /root/dogtagpki/
docker run --name pki2 --cap-add=NET_ADMIN -v /root/dogtagpki/pki:/root/pki -dit pki /bin/sh -c "/sbin/ip addr add 172.17.0.08 dev eth0; bash"

# Running CA tests in the container.
docker exec -d pki2 py.test --cov=/root/pki/dogtag/pytest/cli/ca/ --multihost-config=/root/pki/dogtag/pytest/cli/quickinstall/mhc.yaml /root/pki/dogtag/pytest/cli/ca/ --cov-config=/root/pki/dogtag/pytest/cli/.coveragerc --cov-report xml
docker exec -d pki2 py.test --cov=/root/pki/dogtag/pytest/cli/kra/ --multihost-config=/root/pki/dogtag/pytest/cli/quickinstall/mhc.yaml /root/pki/dogtag/pytest/cli/kra/ --cov-config=/root/pki/dogtag/pytest/cli/.coveragerc --cov-report xml
docker exec -d pki2 py.test --cov=/root/pki/dogtag/pytest/cli/ocsp/ --multihost-config=/root/pki/dogtag/pytest/cli/quickinstall/mhc.yaml /root/pki/dogtag/pytest/cli/ocsp/ --cov-config=/root/pki/dogtag/pytest/cli/.coveragerc --cov-report xml
docker exec -d pki2 py.test --cov=/root/pki/dogtag/pytest/cli/tks/ --multihost-config=/root/pki/dogtag/pytest/cli/quickinstall/mhc.yaml /root/pki/dogtag/pytest/cli/tks/ --cov-config=/root/pki/dogtag/pytest/cli/.coveragerc --cov-report xml
docker exec -d pki2 py.test --cov=/root/pki/dogtag/pytest/cli/tps/ --multihost-config=/root/pki/dogtag/pytest/cli/quickinstall/mhc.yaml /root/pki/dogtag/pytest/cli/tps/ --cov-config=/root/pki/dogtag/pytest/cli/.coveragerc --cov-report xml

