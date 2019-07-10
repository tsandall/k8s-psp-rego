package psp

violations[name] {
    some name
    fsgroup_violation[name]
}

fsgroup_violation[name] {
    some name
    pol := psps[name]
    pol.rule == "MayRunAs"
    # MayRunAs does not require an FSGRoup in the pod spec
    fsGroup := input.spec.securityContext.fsGroup
    not fsgroup_range_allows(pol, fsGroup)
}

fsgroup_violation[name] {
    some name
    pol := psps[name]
    pol.rule == "MustRunAs"
    # MustRunAs requires an FSGroup in the pod spec
    not fsgroup_range_allows_pod_spec(pol, input.spec)
}

fsgroup_range_allows(pol, fsGroup) {
    some i
    pol.ranges[i].min <= fsGroup
    pol.ranges[i].max >= fsGroup
}

fsgroup_range_allows_pod_spec(pol, spec) {
    fsGroup := spec.securityContext.fsGroup
    not fsgroup_range_allows(pol, fsGroup)
}