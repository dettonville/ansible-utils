
# Run module integration test

## Setup

```shell
$ PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"
$ COLLECTION_DIR=${PROJECT_DIR}/collections/ansible_collections/dettonville/util
$ echo "COLLECTION_DIR=${COLLECTION_DIR}"
$ cd ${COLLECTION_DIR}
``` 

## Module update_hosts

Module integration test

```shell
$ ansible-test integration -v --docker --python 3.10 update_hosts
```

Output:

<span style="color:green;">Falling back to tests in &quot;tests/integration/targets/&quot; because &quot;roles/test/&quot; was not found.</span><br>
<span style="color:green;">Assuming Docker is available on localhost.</span><br>
<span style="color:green;">Run command: docker -v</span><br>
...

* [Full detailed results here](./update_hosts.results.md)
* [Full detailed colorized results here](./update_hosts.results.pdf)
