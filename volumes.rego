package psp

violations[name] {
    some name
    volume_violation[name]
}

volume_violation[name] {
    some name, volume
    pol := psps[name]
    input.spec.volumes[volume]
    not volume_type_allowed(pol, volume)
}

volume_type_allowed(pol, _) {
    pol.volumes[_] == "*"
}

volume_type_allowed(pol, volume) {
    pol.volumes[_] == volume
}