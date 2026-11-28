package openshell

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
)

// readBackRule is what the read-back does with one field of what the gateway returns.
type readBackRule int

const (
	// readCompared: the field must read back as plimsoll sent or requires it; a changed
	// value refuses the run.
	readCompared readBackRule = iota + 1
	// readRefused: plimsoll never sets the field; a set value refuses the run (for an
	// enum or a string with an accepted default, any value but that default).
	readRefused
	// readWalked: a message the read-back checks field by field; each of its fields has
	// its own row.
	readWalked
	// readChecked: checked in part, as the reason says, by cases of its own
	// (TestReadBackRefusals); no single changed value stands for it.
	readChecked
	// readIgnored: not checked, for the reason given.
	readIgnored
)

// readBackField is one row of readBackFields.
type readBackField struct {
	rule readBackRule
	why  string
}

// readBackRoots are the messages the read-back reads: the sandbox record (verifySandbox)
// and its effective configuration (checkConfig).
var readBackRoots = []protoreflect.MessageDescriptor{
	(&openshellv1.Sandbox{}).ProtoReflect().Descriptor(),
	(&sandboxv1.GetSandboxConfigResponse{}).ProtoReflect().Descriptor(),
}

// readBackFields decides every field under readBackRoots that the vendored OpenShell API
// (third_party/openshell/proto, v0.1.10) defines. unknownField refuses a field the
// generated code does not define, but each re-vendoring turns such fields into known
// ones, which would then pass unless a case compared them.
// TestEveryReadBackFieldIsDecided fails on a field with no row, so a vendoring decides
// each new field here: compared, refused, or ignored with a reason, and the same test
// changes each compared, refused or ignored field and checks the read-back does what its
// row says.
var readBackFields = map[protoreflect.FullName]readBackField{
	// The sandbox record.
	"openshell.v1.Sandbox.metadata": {readChecked, "the id must be present and every label plimsoll sent must read back as sent; the name, times, resource version, workspace and annotations are the gateway's bookkeeping of the object and reach no process"},
	"openshell.v1.Sandbox.spec":     {readWalked, ""},
	"openshell.v1.Sandbox.status":   {readChecked, "observed state, not configuration: waitReady needs phase READY and quotes the conditions when it is not"},
	"openshell.v1.Sandbox.host_key_fingerprint": {readIgnored,
		"the sandbox's SSH host identity, read-only; plimsoll reaches the sandbox through the gateway's exec, never SSH"},
	"openshell.v1.Sandbox.created_from_workload_template": {readRefused,
		"plimsoll creates every sandbox from an inline spec; the v0.1.10 gateway sets this only for a sandbox made from a stored workload template, whose spec is not the one plimsoll sent"},

	// The spec.
	"openshell.v1.SandboxSpec.log_level": {readIgnored, "the log level of OpenShell's own processes in the sandbox; it changes what they log, not what the sandbox can reach"},
	"openshell.v1.SandboxSpec.environment": {readRefused,
		"environment injected into the sandbox runtime; plimsoll injects none"},
	"openshell.v1.SandboxSpec.template": {readWalked, ""},
	"openshell.v1.SandboxSpec.policy":   {readCompared, "the policy sent, compared whole (proto.Equal, unknown fields included)"},
	"openshell.v1.SandboxSpec.providers": {readRefused,
		"credential providers; plimsoll attaches none"},
	"openshell.v1.SandboxSpec.resource_requirements": {readWalked, ""},
	"openshell.v1.SandboxSpec.command": {readCompared,
		"the main process, compared when plimsoll names one (a session's); a run's sandbox sends none and the gateway's default login shell is not compared"},
	"openshell.v1.SandboxSpec.tty": {readIgnored,
		"the v0.1.2 gateway sets it on every sandbox; a terminal on the idle main process reaches nothing"},
	"openshell.v1.SandboxSpec.provider_attachment_epoch": {readIgnored,
		"the gateway's identity for the attached provider set, which must be empty (providers is refused)"},
	"openshell.v1.SandboxSpec.restart_policy": {readRefused,
		"anything but unset or NEVER replaces the runtime after the main process exits, so a session whose main process ended would go on in a new one; v0.1.10 stores unset as NEVER"},

	// The template.
	"openshell.v1.SandboxTemplate.image":              {readCompared, "the configured image"},
	"openshell.v1.SandboxTemplate.runtime_class_name": {readRefused, "another runtime class would change the boundary the tier names"},
	"openshell.v1.SandboxTemplate.agent_socket":       {readRefused, "a socket exposed to the workload; plimsoll exposes none"},
	"openshell.v1.SandboxTemplate.labels":             {readRefused, "labels on the compute platform's resources; plimsoll sets none"},
	"openshell.v1.SandboxTemplate.annotations":        {readRefused, "annotations on the compute platform's resources; plimsoll sets none"},
	"openshell.v1.SandboxTemplate.environment":        {readRefused, "environment injected by the template; plimsoll injects none"},
	"openshell.v1.SandboxTemplate.resources":          {readCompared, "the memory and CPU limits sent"},
	"openshell.v1.SandboxTemplate.user_namespaces":    {readRefused, "plimsoll sets none; a set value changes the user mapping the tier was measured with"},
	"openshell.v1.SandboxTemplate.driver_config":      {readCompared, "the driver config sent (the /tmp size), or none"},

	// The portable resource requirements.
	"openshell.v1.ResourceRequirements.gpu": {readRefused,
		"its presence is a GPU request (the proto's comment; the v0.1.10 gateway's sandbox_gpu_requested), a host device plimsoll never asks for"},

	// The effective configuration.
	"openshell.sandbox.v1.GetSandboxConfigResponse.policy":      {readCompared, "the policy sent, compared whole (proto.Equal, unknown fields included)"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.version":     {readIgnored, "a counter the gateway raises at each policy revision; the policy and its hash are compared"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.policy_hash": {readCompared, "the hash plimsoll computes of the policy sent (policyHash)"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.settings": {readChecked,
		"agent_policy_proposals_enabled must be proven off (proposalsOff); the other keys v0.1.10 registers are ocsf_json_enabled and ocsf_schema_version (logging) and proposal_approval_mode, which governs only proposals, and those are off"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.config_revision": {readIgnored, "a fingerprint of the policy and settings, both checked"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.policy_source":   {readCompared, "must be SANDBOX: a gateway-wide policy replaces the one plimsoll sent"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.global_policy_version": {readIgnored,
		"zero unless the policy source is GLOBAL, which is refused"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.provider_env_revision": {readIgnored,
		"a fingerprint of the attached providers' credential inputs; the spec must attach none (providers is refused)"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.supervisor_middleware_services": {readRefused,
		"operator-registered services the sandbox's supervisor connects to and that see the traffic the policy binds to them; the v0.1.10 gateway lists those the effective policy requires, and plimsoll's policy names none (no network_middlewares), so a listed service is one plimsoll did not ask for"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.workspace": {readIgnored,
		"the workspace's name; plimsoll selects its workspace on every call"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.policy_validation_failure_mode": {readRefused,
		"anything but fail_closed (or unset, which the supervisor reads as fail_closed): under retain_last_valid a supervisor that rejects a policy generation keeps the last one it loaded, so the policy read back here would no longer be the one enforced; under fail_closed it denies new egress, never looser than plimsoll's policy, which allows none"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.extension_authentication_enabled": {readIgnored,
		"whether the gateway mints credentials for supervisor middleware services; the v0.1.10 supervisor uses it only when it connects to one, and supervisor_middleware_services must be empty"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.provider_attachment_epoch": {readIgnored,
		"the gateway's identity for the attached provider set, which must be empty"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.configuration_admitted": {readCompared, "must be true: the gateway validated the whole configuration"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.configuration_error": {readIgnored,
		"diagnostic text, quoted in the refusal when the configuration is not admitted"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.configuration_instance_id": {readIgnored,
		"a registration fence for a new supervisor, kept by the supervisor"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.settings_revision": {readIgnored,
		"a counter of the sandbox's settings row; the settings are checked"},
	"openshell.sandbox.v1.GetSandboxConfigResponse.service_routes": {readRefused,
		"application routes into the sandbox; plimsoll exposes none"},
}
