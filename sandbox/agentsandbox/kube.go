package agentsandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// kube is the slice of the Kubernetes API the provider uses, over net/http: JSON, one API
// server, a bearer token read from its file at every request (a projected service account
// token is rotated in place), and no redirect followed (one would carry the token wherever
// it pointed). No client-go: the provider reads seven kinds of object and writes one.
type kube struct {
	base      string
	hc        *http.Client
	tokenFile string
}

// maxKubeBody bounds one API answer read into memory. A list of a namespace's network
// policies or claims is the largest the provider reads; 8 MiB holds thousands.
const maxKubeBody = 8 << 20

func newKube(base, caFile, tokenFile string) (*kube, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("agentsandbox: the API server's CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("agentsandbox: the API server's CA file holds no PEM certificate")
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		Proxy:               nil, // the token goes to the API server and nowhere else
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &kube{base: strings.TrimRight(base, "/"), tokenFile: tokenFile, hc: &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// statusError is an answer the API server gave with a non-2xx status.
type statusError struct {
	Code    int
	Reason  string
	Message string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("kubernetes %d %s: %s", e.Code, e.Reason, e.Message)
}

func isNotFound(err error) bool {
	var s *statusError
	return errors.As(err, &s) && s.Code == http.StatusNotFound
}

func (k *kube) token() (string, error) {
	raw, err := os.ReadFile(k.tokenFile)
	if err != nil {
		return "", fmt.Errorf("agentsandbox: the API token: %w", err)
	}
	t := strings.TrimSpace(string(raw))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", errors.New("agentsandbox: the API token file holds no single token")
	}
	return t, nil
}

// do sends one request. body, when not nil, is sent as JSON; out, when not nil, receives
// the decoded answer.
func (k *kube) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/apis/") || strings.ContainsAny(path, "?#%") || strings.Contains(path, "..") {
		return fmt.Errorf("agentsandbox: API path %q", path)
	}
	target := k.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	tok, err := k.token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxKubeBody+1))
	if err != nil {
		return err
	}
	if len(raw) > maxKubeBody {
		return fmt.Errorf("agentsandbox: an API answer over %d bytes", maxKubeBody)
	}
	if resp.StatusCode/100 != 2 {
		e := &statusError{Code: resp.StatusCode}
		var st struct{ Reason, Message string }
		if json.Unmarshal(raw, &st) == nil {
			e.Reason, e.Message = st.Reason, cut(st.Message, 512)
		}
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (k *kube) get(ctx context.Context, path string, out any) error {
	return k.do(ctx, http.MethodGet, path, nil, nil, out)
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// API paths. Names reach them only after validName.
const (
	extensionsAPI = "/apis/extensions.agents.x-k8s.io/v1beta1"
	agentsAPI     = "/apis/agents.x-k8s.io/v1beta1"
)

func claimsPath(ns string) string      { return extensionsAPI + "/namespaces/" + ns + "/sandboxclaims" }
func claimPath(ns, name string) string { return claimsPath(ns) + "/" + name }
func warmPoolPath(ns, name string) string {
	return extensionsAPI + "/namespaces/" + ns + "/sandboxwarmpools/" + name
}
func templatePath(ns, name string) string {
	return extensionsAPI + "/namespaces/" + ns + "/sandboxtemplates/" + name
}
func sandboxPath(ns, name string) string {
	return agentsAPI + "/namespaces/" + ns + "/sandboxes/" + name
}
func podPath(ns, name string) string { return "/api/v1/namespaces/" + ns + "/pods/" + name }
func networkPoliciesPath(ns string) string {
	return "/apis/networking.k8s.io/v1/namespaces/" + ns + "/networkpolicies"
}
func runtimeClassPath(name string) string { return "/apis/node.k8s.io/v1/runtimeclasses/" + name }
func nodePath(name string) string         { return "/api/v1/nodes/" + name }

// Object metadata and status are partial views. Pod specs and everything decoded inside
// them are closed schemas: new execution or privilege controls require an explicit review.

type objectMeta struct {
	Name              string            `json:"name,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
	OwnerReferences   []ownerReference  `json:"ownerReferences,omitempty"`
}

type ownerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
}

// controlledBy reports whether m's controller is the object of kind with this uid.
func (m objectMeta) controlledBy(kind, uid string) bool {
	for _, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.Kind == kind && o.UID == uid
		}
	}
	return false
}

type condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

func conditionTrue(cs []condition, typ string) bool {
	for _, c := range cs {
		if c.Type == typ {
			return c.Status == "True"
		}
	}
	return false
}

type claim struct {
	APIVersion string      `json:"apiVersion,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Meta       objectMeta  `json:"metadata"`
	Spec       claimSpec   `json:"spec"`
	Status     claimStatus `json:"status,omitzero"`
}

type claimSpec struct {
	WarmPoolRef struct {
		Name string `json:"name"`
	} `json:"warmPoolRef"`
	Lifecycle *claimLifecycle `json:"lifecycle,omitempty"`
}

type claimLifecycle struct {
	ShutdownTime   string `json:"shutdownTime"`
	ShutdownPolicy string `json:"shutdownPolicy"`
}

type claimStatus struct {
	Conditions []condition `json:"conditions,omitempty"`
	Sandbox    struct {
		Name   string   `json:"name,omitempty"`
		PodIPs []string `json:"podIPs,omitempty"`
	} `json:"sandbox,omitzero"`
}

type claimList struct {
	Items    []claim `json:"items"`
	Metadata struct {
		Continue string `json:"continue,omitempty"`
	} `json:"metadata"`
}

type warmPool struct {
	Meta objectMeta `json:"metadata"`
	Spec struct {
		SandboxTemplateRef struct {
			Name string `json:"name"`
		} `json:"sandboxTemplateRef"`
	} `json:"spec"`
}

type template struct {
	Meta objectMeta `json:"metadata"`
	Spec struct {
		NetworkPolicyManagement string `json:"networkPolicyManagement,omitempty"`
		PodTemplate             struct {
			Spec podSpec `json:"spec"`
		} `json:"podTemplate"`
	} `json:"spec"`
}

type sandboxObject struct {
	Meta   objectMeta `json:"metadata"`
	Status struct {
		Conditions []condition `json:"conditions,omitempty"`
		PodIPs     []string    `json:"podIPs,omitempty"`
	} `json:"status"`
}

type pod struct {
	Meta   objectMeta `json:"metadata"`
	Spec   podSpec    `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		PodIP             string `json:"podIP"`
		ContainerStatuses []struct {
			Name    string `json:"name"`
			ImageID string `json:"imageID"`
			Ready   bool   `json:"ready"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type podSpec struct {
	// Scheduling, accounting and identity defaults added by Kubernetes and RuntimeClass
	// admission. These do not grant the guest a capability; the boundary checks below
	// apply independently of where the scheduler places the pod.
	NodeSelector                  map[string]string `json:"nodeSelector,omitempty"`
	Overhead                      map[string]string `json:"overhead,omitempty"`
	Tolerations                   []toleration      `json:"tolerations,omitempty"`
	SchedulerName                 string            `json:"schedulerName,omitempty"`
	Priority                      *int32            `json:"priority,omitempty"`
	PreemptionPolicy              string            `json:"preemptionPolicy,omitempty"`
	ServiceAccount                string            `json:"serviceAccount,omitempty"`
	ServiceAccountName            string            `json:"serviceAccountName,omitempty"`
	RestartPolicy                 string            `json:"restartPolicy,omitempty"`
	TerminationGracePeriodSeconds *int64            `json:"terminationGracePeriodSeconds,omitempty"`
	EnableServiceLinks            *bool             `json:"enableServiceLinks,omitempty"`
	// NodeName is the node the scheduler put the pod on; a template leaves it unset.
	NodeName                     string     `json:"nodeName,omitempty"`
	RuntimeClassName             *string    `json:"runtimeClassName,omitempty"`
	AutomountServiceAccountToken *bool      `json:"automountServiceAccountToken,omitempty"`
	HostNetwork                  bool       `json:"hostNetwork,omitempty"`
	HostPID                      bool       `json:"hostPID,omitempty"`
	HostIPC                      bool       `json:"hostIPC,omitempty"`
	ShareProcessNamespace        *bool      `json:"shareProcessNamespace,omitempty"`
	DNSPolicy                    string     `json:"dnsPolicy,omitempty"`
	DNSConfig                    *dnsConfig `json:"dnsConfig,omitempty"`
	SecurityContext              *struct {
		SeccompProfile *seccompProfile `json:"seccompProfile,omitempty"`
	} `json:"securityContext,omitempty"`
	InitContainers      []json.RawMessage `json:"initContainers,omitempty"`
	EphemeralContainers []json.RawMessage `json:"ephemeralContainers,omitempty"`
	Containers          []container       `json:"containers"`
	Volumes             []volume          `json:"volumes,omitempty"`
}

// UnmarshalJSON rejects unknown fields recursively, including in containers, probes,
// security contexts and mounts. Metadata and status outside the spec stay extensible.
func (s *podSpec) UnmarshalJSON(raw []byte) error {
	type spec podSpec
	var decoded spec
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("pod spec: %w", err)
	}
	*s = podSpec(decoded)
	return nil
}

type toleration struct {
	Key               string `json:"key,omitempty"`
	Operator          string `json:"operator,omitempty"`
	Value             string `json:"value,omitempty"`
	Effect            string `json:"effect,omitempty"`
	TolerationSeconds *int64 `json:"tolerationSeconds,omitempty"`
}

type dnsConfig struct {
	Nameservers []string          `json:"nameservers,omitempty"`
	Searches    []string          `json:"searches,omitempty"`
	Options     []json.RawMessage `json:"options,omitempty"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	Command         []string         `json:"command,omitempty"`
	Args            []string         `json:"args,omitempty"`
	SecurityContext *securityContext `json:"securityContext,omitempty"`
	VolumeMounts    []volumeMount    `json:"volumeMounts,omitempty"`
	ImagePullPolicy string           `json:"imagePullPolicy,omitempty"`
	Ports           []containerPort  `json:"ports,omitempty"`
	ReadinessProbe  *probe           `json:"readinessProbe,omitempty"`
	LivenessProbe   *probe           `json:"livenessProbe,omitempty"`
	StartupProbe    *probe           `json:"startupProbe,omitempty"`
	Lifecycle       *struct {
		PostStart *handler `json:"postStart,omitempty"`
		PreStop   *handler `json:"preStop,omitempty"`
	} `json:"lifecycle,omitempty"`
	// TerminationMessagePath is the file the kubelet mounts from the node's disk, mode
	// 0666, for the container's last words.
	TerminationMessagePath   string `json:"terminationMessagePath,omitempty"`
	TerminationMessagePolicy string `json:"terminationMessagePolicy,omitempty"`
	Resources                struct {
		Limits   map[string]string `json:"limits,omitempty"`
		Requests map[string]string `json:"requests,omitempty"`
	} `json:"resources"`
}

type containerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	HostPort      int    `json:"hostPort,omitempty"`
	HostIP        string `json:"hostIP,omitempty"`
}

// Only network handlers are accepted. Exec is retained as raw JSON so even an explicit
// null is refused, rather than silently disappearing through a nil pointer.
type handler struct {
	Exec    json.RawMessage `json:"exec,omitempty"`
	HTTPGet *struct {
		Host        string          `json:"host,omitempty"`
		Path        string          `json:"path,omitempty"`
		Port        json.RawMessage `json:"port"`
		Scheme      string          `json:"scheme,omitempty"`
		HTTPHeaders []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"httpHeaders,omitempty"`
	} `json:"httpGet,omitempty"`
	TCPSocket *struct {
		Host string          `json:"host,omitempty"`
		Port json.RawMessage `json:"port"`
	} `json:"tcpSocket,omitempty"`
}

type probe struct {
	handler
	GRPC *struct {
		Port    int     `json:"port"`
		Service *string `json:"service,omitempty"`
	} `json:"grpc,omitempty"`
	InitialDelaySeconds           int32  `json:"initialDelaySeconds,omitempty"`
	TimeoutSeconds                int32  `json:"timeoutSeconds,omitempty"`
	PeriodSeconds                 int32  `json:"periodSeconds,omitempty"`
	SuccessThreshold              int32  `json:"successThreshold,omitempty"`
	FailureThreshold              int32  `json:"failureThreshold,omitempty"`
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
}

type volumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	SubPath   string `json:"subPath,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type seccompProfile struct {
	Type             string `json:"type"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

type securityContext struct {
	RunAsUser                *int64          `json:"runAsUser,omitempty"`
	RunAsGroup               *int64          `json:"runAsGroup,omitempty"`
	SeccompProfile           *seccompProfile `json:"seccompProfile,omitempty"`
	Privileged               *bool           `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem,omitempty"`
	Capabilities             *struct {
		Add  []string `json:"add,omitempty"`
		Drop []string `json:"drop,omitempty"`
	} `json:"capabilities,omitempty"`
}

// volume keeps every key of a volume, so a source the provider does not allow (a host
// path, a projected service account token) is seen whatever its name.
type volume map[string]json.RawMessage

type networkPolicyList struct {
	Items []networkPolicy `json:"items"`
}

type networkPolicy struct {
	Meta objectMeta `json:"metadata"`
	Spec struct {
		PodSelector labelSelector     `json:"podSelector"`
		PolicyTypes []string          `json:"policyTypes,omitempty"`
		Ingress     []ingressRule     `json:"ingress,omitempty"`
		Egress      []json.RawMessage `json:"egress,omitempty"`
	} `json:"spec"`
}

type ingressRule struct {
	From  []json.RawMessage `json:"from,omitempty"`
	Ports []struct {
		Protocol string          `json:"protocol,omitempty"`
		Port     json.RawMessage `json:"port,omitempty"`
		EndPort  *int            `json:"endPort,omitempty"`
	} `json:"ports,omitempty"`
}

type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels,omitempty"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values,omitempty"`
	} `json:"matchExpressions,omitempty"`
}

// runtimeClass is a RuntimeClass as the provider reads it: the handler decides the tier,
// and overhead and scheduling (kept raw) are bound with the UID and the handler to the
// startup smoke test (classSum).
type runtimeClass struct {
	Meta       objectMeta      `json:"metadata"`
	Handler    string          `json:"handler"`
	Overhead   json.RawMessage `json:"overhead,omitempty"`
	Scheduling json.RawMessage `json:"scheduling,omitempty"`
}

// node is a node as the vm tier's per-pod check reads it: the boot ID its kubelet
// reports, which is the node kernel's own.
type node struct {
	Meta   objectMeta `json:"metadata"`
	Status struct {
		NodeInfo struct {
			BootID string `json:"bootID"`
		} `json:"nodeInfo"`
	} `json:"status"`
}
