package sandbox

import "regexp"

// instanceForm is a typed instance reference: a kind of lowercase letters, digits and
// "-", a colon, and an ID in the trace charset, at most 160 bytes in all.
var instanceForm = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9._:-]{1,127}$`)

// ValidInstance reports whether s is a result's instance: "" (the provider names none) or
// a typed reference such as "k8s-pod-uid:" and a pod's UID. It is never a path or a
// name, so a record that names it carries only an opaque join key.
func ValidInstance(s string) bool { return s == "" || instanceForm.MatchString(s) }

// PodInstance is the instance reference of a Kubernetes pod by the UID the API server
// gave it, or "" when uid does not fit the form.
func PodInstance(uid string) string {
	if s := "k8s-pod-uid:" + uid; instanceForm.MatchString(s) {
		return s
	}
	return ""
}
