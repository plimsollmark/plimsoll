#!/bin/sh
# Captures the five fixture logs on a kind cluster and writes them to ../runsclog/testdata.
#
# Needs: a kind cluster with gVisor's containerd shim (io.containerd.runsc.v1), and in its
# node the handler in handler.toml and the options in runsc-receipt.toml, plus a RuntimeClass
# gvisor-receipt with handler runsc-receipt. -install puts those in place (as root inside
# the node, restarting containerd there; running pods keep running).
#
#   examples/dependency-receipt/fixtures/capture.sh [-install]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cluster=${KIND_CLUSTER:-plimsoll-as}
node=$cluster-control-plane
if [ "${1:-}" = -install ]; then
	docker exec "$node" mkdir -p /etc/containerd/runsc-observe.d
	docker cp "$here/runsc-receipt.toml" "$node:/etc/containerd/runsc-observe.d/runsc-receipt.toml"
	if ! docker exec "$node" grep -q 'runtimes.runsc-receipt]' /etc/containerd/runsc-observe.d/handler.toml 2>/dev/null; then
		docker exec -i "$node" sh -c 'cat >> /etc/containerd/runsc-observe.d/handler.toml' < "$here/handler.toml"
	fi
	docker exec "$node" grep -q 'runsc-observe.d/handler.toml' /etc/containerd/config.toml ||
		{ echo "add /etc/containerd/runsc-observe.d/handler.toml to imports in the node's config.toml" >&2; exit 1; }
	docker exec "$node" systemctl restart containerd
	printf 'apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata: {name: gvisor-receipt}\nhandler: runsc-receipt\n' | kubectl apply -f -
fi
docker build -q -t plimsoll-dependency-fixtures:dev "$here" >/dev/null
kind load docker-image plimsoll-dependency-fixtures:dev --name "$cluster" >/dev/null
for name in quiet builds canary network child; do
	pod=fx-$name
	kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: $pod}
spec:
  runtimeClassName: gvisor-receipt
  restartPolicy: Never
  containers:
  - name: c
    image: plimsoll-dependency-fixtures:dev
    imagePullPolicy: Never
    command: ["node", "/driver.mjs", "$name"]
YAML
	kubectl wait "pod/$pod" --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s >/dev/null
	sandbox=$(docker exec "$node" crictl pods --name "^$pod\$" -q | head -1)
	# runsc writes its closing line when the sandbox stops, so the log is read after the pod goes.
	kubectl delete pod "$pod" --wait=true >/dev/null
	docker exec "$node" sh -c "cat /var/log/runsc-observe/$sandbox/*.boot.txt" | gzip -9 -n > "$here/../runsclog/testdata/$name.boot.json.gz"
	docker exec "$node" rm -r "/var/log/runsc-observe/$sandbox"
	echo "$name: $(gzip -dc "$here/../runsclog/testdata/$name.boot.json.gz" | wc -c) bytes"
done
