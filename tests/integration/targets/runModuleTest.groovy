#!/usr/bin/env groovy

import jenkins.branch.*
import jenkins.model.Jenkins

import com.dettonville.pipeline.utils.logging.LogLevel
import com.dettonville.pipeline.utils.logging.Logger
import com.dettonville.pipeline.utils.logging.JenkinsLogger

import com.dettonville.pipeline.utils.JsonUtils

// import groovy.transform.Field
// @Field String scriptName = this.class.getName()
// @Field JenkinsLogger log = new JenkinsLogger(this, prefix: scriptName)
// @Field JenkinsLogger log = new JenkinsLogger(this)
// @Field Logger log = new Logger(this)

Logger log = new Logger(this)

//Logger log = new Logger(this, LogLevel.INFO)
//String logPrefix="runModuleTest():"

Map config = [:]

List testTags = [
    "export_dicts",
    "git_pacp",
    "remove_dict_keys",
    "remove_sensitive_keys",
    "sort_dict_list",
    "test_results_logger",
    "to_markdown",
    "all"
]

config.testCaseIdDefault = "01"
config.testTagsParam = testTags
// config.ansiblePlaybookDir = "./tests/integration/targets"
config.ansiblePlaybookDir = "./collections/ansible_collections/dettonville/utils/tests/integration/targets"
// config.ansibleInventory = "${config.ansiblePlaybookDir}/_test_inventory/"

// log.info("config=${JsonUtils.printToJsonString(config)}")
log.info("config=${config}")

runAnsibleCollectionTest(config)
