package psp

# 1. On matching
# --------------
# This policy accepts a pod definition and determines
# if the pod can be allowed in the cluster per the PSPs
# installed on the cluster.
#
# See special logic about ignoring certain updates that
# are done by GC. https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/admission/security/podsecuritypolicy/admission.go#L195


# If there are no matches then deny the pod.
# TODO(tsandall): configurable? https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/admission/security/podsecuritypolicy/admission.go#L224
default allow = false

# if there are any psps that permit, allow, otherwise deny
allow {
    some psp
    matches[psp]
    not violations[psp]
}

# TODO(tsandall): implement matching
matches[name] {
    some name
    data.kubernetes.podsecuritypolicies[name]
}

psps[name] = psp {
    some name
    psp := data.kubernetes.podsecuritypolicies[name]
}

input_containers[c] {
    c := input.spec.containers[_]
}

input_containers[c] {
    c := input.spec.initContainers[_]
}