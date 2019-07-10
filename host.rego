package psp

violations[name] {
    some name
    hostPID_violation[name]
}

violations[name] {
    some name
    hostIPC_violation[name]
}

violations[name] {
    some name
    hostNetwork_violation[name]
}

violations[name] {
    some name
    hostPort_violation[name]
}

hostPID_violation[name] {
    some name
    pol := psps[name]
    not pol.spec.hostPID
    input.spec.securityContext.hostPID
}

hostIPC_violation[name] {
    some name
    pol := psps[name]
    not pol.spec.hostIPC
    input.spec.securityContext.hostIPC
}

hostNetwork_violation[name] {
    some name
    pol := psps[name]
    not pol.spec.hostNetwork
    input.spec.securityContext.hostNetwork
}

hostPort_violation[name] {
    some name
    pol := psps[name]
    hostPort := input_containers[_].ports[_].hostPort
    hostPort > 0
    not any_hostPort_allows(pol, hostPort)
}

any_hostPort_allows(pol, hostPort) {
    some i
    pol.spec.hostPorts[i].min <= hostPort
    pol.spec.hostPorts[i].max >= hostPort
}