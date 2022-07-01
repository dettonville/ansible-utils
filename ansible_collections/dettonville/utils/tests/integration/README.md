
# Run module integration test

## Setup

```shell
$ PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"
$ COLLECTION_DIR=${PROJECT_DIR}/collections/ansible_collections/dettonville/utils
$ echo "COLLECTION_DIR=${COLLECTION_DIR}"
$ cd ${COLLECTION_DIR}
``` 

## Module export_dicts

Module integration test

```shell
$ ansible-test integration -v --docker --python 3.10 export_dicts
```

Output:

```shell
ansible-test integration -v --color --docker --python 3.10 export_dicts | aha > tests/integration/test-results.export_dicts.html

Falling back to tests in "tests/integration/targets/" because "roles/test/" was not found.
Assuming Docker is available on localhost.
Run command: docker -v
Detected "docker" container runtime version: Docker version 20.10.16, build aa7e414
Starting new "ansible-test-controller-Nl1njsLi" container.
Run command: docker image inspect quay.io/ansible/default-test-container:4.2.0
Run command: docker run --volume /sys/fs/cgroup:/sys/fs/cgroup:ro --privileged=false --security-opt seccomp=unconfined --volume /var/run/docker.sock:/var/run/docker.sock --name ansible-test-controller-Nl1njsLi -d quay.io/ansible/default-test-container:4.2.0
...


PLAY RECAP *********************************************************************
testhost                   : ok=101  changed=19   unreachable=0    failed=0    skipped=9    rescued=0    ignored=4   

Run command: docker exec -i ansible-test-controller-Nl1njsLi sh -c 'tar cf - -C /root/ansible_collections/dettonville/inventory/tests --exclude .tmp output | gzip'
Run command: tar oxzf - -C /Users/ljohnson/repos/silex/alsac/dettonville/collections/ansible_collections/dettonville/inventory/tests
Run command: docker rm -f ansible-test-controller-Nl1njsLi

```

* [Full detailed results here](./test-results.export_dicts.md)
* [Full detailed colorized results here](./test-results.export_dicts.pdf)
