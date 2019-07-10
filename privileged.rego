package psp

violations[name] {
    some name
    privileged_violation[name]
}

privileged_violation[name] {
    some name
    pol := psps[name]
    not pol.spec.privileged
    input_containers[_].spec.securityContext.privileged
}