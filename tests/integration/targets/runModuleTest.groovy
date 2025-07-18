#!/usr/bin/env groovy
import com.dettonville.pipeline.utils.logging.LogLevel
import com.dettonville.pipeline.utils.logging.Logger

import com.dettonville.pipeline.utils.JsonUtils

Logger.init(this, LogLevel.INFO)
Logger log = new Logger(this)
String logPrefix="runModuleTest():"

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
config.ansiblePlaybookDir = "./tests/integration/targets"
// config.ansibleInventory = "${config.ansiblePlaybookDir}/_test_inventory/"

log.info("${logPrefix} config=${JsonUtils.printToJsonString(config)}")

runAnsibleCollectionTest(config)
