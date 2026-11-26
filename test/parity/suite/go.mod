module authz-agent/test/parity/suite

go 1.26.8

require (
	github.com/google/go-cmp v0.7.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

require authz-agent/test/suitecheck v0.0.0

replace authz-agent/test/suitecheck => ../../suitecheck
