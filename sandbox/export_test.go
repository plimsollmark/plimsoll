package sandbox

// Unexported values the external tests (package sandbox_test) need.

// DockerRemoveBudget is the longest a docker session's container removal takes, so
// the longest its Done can trail its end (sessiontest.Config.Teardown).
const DockerRemoveBudget = dockerRemoveBudget

// HeavyDockerTest admits one of the docker suite's heaviest tests (heavyDockerTest).
var HeavyDockerTest = heavyDockerTest
