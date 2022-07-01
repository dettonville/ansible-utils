

Run role test

```shell
$ PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"
$ echo ${PROJECT_DIR}
$ cd ${PROJECT_DIR}
$ tests/test-update-inventory-role.sh

SCRIPT_DIR=[/Users/ljohnson/repos/silex/alsac/dettonville/tests]
PROJECT_DIR=/Users/ljohnson/repos/silex/alsac/dettonville

PLAY [TEST update-inventory-role | Update hosts in repo inventory] *************
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.017)       0:00:00.017 ******** 

TASK [dettonville.inventory.update_repo_inventory : Include vars] ***************
ok: [localhost]
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.044)       0:00:00.062 ******** 

TASK [dettonville.inventory.update_repo_inventory : Set facts] ******************
ok: [localhost]
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.040)       0:00:00.102 ******** 

TASK [dettonville.inventory.update_repo_inventory : Display role params] ********
ok: [localhost] => 
  msg:
    __update_inventory_repo__git_ssh_private_key_path: /Users/ljohnson/.ssh/ansible_repo.key
    update_inventory_repo__file: tests/inventory/site2.yml
    update_inventory_repo__repo_branch: master
    update_inventory_repo__repo_scheme: ssh
    update_inventory_repo__repo_url: ssh://git@gitea.admin.dettonville.int:2222/infra/report-inventory-facts.git
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.027)       0:00:00.130 ******** 

TASK [dettonville.inventory.update_repo_inventory : Set facts] ******************
ok: [localhost]
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.040)       0:00:00.170 ******** 

TASK [dettonville.inventory.update_repo_inventory : Display __update_inventory_repo__ssh_params] ***
ok: [localhost] => 
  __update_inventory_repo__ssh_params:
    accept_hostkey: true
    key_file: /Users/ljohnson/.ssh/ansible_repo.key
Wednesday 29 June 2022  17:51:23 -0400 (0:00:00.028)       0:00:00.199 ******** 

TASK [dettonville.inventory.update_repo_inventory : Ensure git private key is present at /Users/ljohnson/.ssh/ansible_repo.key] ***
ok: [localhost]
Wednesday 29 June 2022  17:51:24 -0400 (0:00:00.740)       0:00:00.939 ******** 

TASK [dettonville.inventory.update_repo_inventory : Add hosts to inventory file at tests/inventory/site2.yml] ***
ok: [localhost]
Wednesday 29 June 2022  17:51:28 -0400 (0:00:04.310)       0:00:05.250 ******** 

TASK [dettonville.inventory.update_repo_inventory : Display update_hosts_to_repo_result] ***
ok: [localhost] => 
  update_hosts_to_repo_result:
    changed: false
    failed: false
    message: No changes required for tests/inventory/site2.yml

PLAY RECAP *********************************************************************
localhost                  : ok=8    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

Wednesday 29 June 2022  17:51:28 -0400 (0:00:00.032)       0:00:05.283 ******** 
=============================================================================== 
dettonville.inventory.update_repo_inventory : Add hosts to inventory file at tests/inventory/site2.yml --- 4.31s
dettonville.inventory.update_repo_inventory : Ensure git private key is present at /Users/ljohnson/.ssh/ansible_repo.key --- 0.74s
dettonville.inventory.update_repo_inventory : Include vars --------------- 0.04s
dettonville.inventory.update_repo_inventory : Set facts ------------------ 0.04s
dettonville.inventory.update_repo_inventory : Set facts ------------------ 0.04s
dettonville.inventory.update_repo_inventory : Display update_hosts_to_repo_result --- 0.03s
dettonville.inventory.update_repo_inventory : Display __update_inventory_repo__ssh_params --- 0.03s
dettonville.inventory.update_repo_inventory : Display role params -------- 0.03s
Playbook run took 0 days, 0 hours, 0 minutes, 5 seconds

```
