
Map config = [:]

config.configFileSanity = ".jenkins/ansible-test-sanity.yml"
config.configFileUnits = ".jenkins/ansible-test-units.yml"

deployAnsibleCollection(config)
