
# Support running ansible-test on collections outside a collection root

I was able to get around this by putting all the code for the collection in `{...}/ansible_collections/{namespace}/{collection}/`, then creating sym-links from the project's root directory out to the items in `{...}/ansible_collections/{namespace}/{collection}/`.

It looks something like this:

```
.
├── README.md -> ansible_collections/dettonville/utils/README.md
├── ansible_collections
│   └── dettonville
│       └── utils
│           ├── README.md
│           ├── galaxy.yml
│           ├── plugins
│           ├── roles
│           └── tests
├── galaxy.yml -> ansible_collections/dettonville/utils/galaxy.yml
├── plugins -> ansible_collections/dettonville/utils/plugins
├── roles -> ansible_collections/dettonville/utils/roles
└── tests -> ansible_collections/dettonville/utils/tests
9 directories, 4 files
```

Running `ansible-test` from within `ansible_collections/dettonville/utils/` works fine.

I tried creating the sym-links from `ansible_collections/dettonville/utils/` back to the items in the project root directly, but that did not work.

This hack seems to work just fine using `ansible-galaxy collection install git+https://github.com/...`, have not tried it with a packaged module.

An example of this layout can be seen in [https://github.com/pedrohdz/ansible-collection-devenv](https://github.com/pedrohdz/ansible-collection-devenv).

## Reference

* https://github.com/ansible/ansible/issues/60215
* https://github.com/ansible/ansible/issues/60215#issuecomment-841212370
