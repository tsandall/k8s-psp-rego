package psp

violations[name] {
    some name
    hostpath_violation[name]
}

hostpath_violation[name] {
    some volume_name
    pol := psps[name]
    hostpath_volumes[volume_name]
    not hostpath_allowed(pol, volume_name)
}

hostpath_allowed(pol, _) {
    pol.spec.allowedHostPaths == []
}

hostpath_allowed(pol, volume_name) {
    allowed := matching_allowed_hostpath(pol, volume_name)
    not allowed.readOnly
}

hostpath_allowed(pol, volume_name) {
    allowed := matching_allowed_hostpath(pol, volume_name)
    allowed.readOnly
    not writeable_volume_mounts[volume_name]
}

matching_allowed_hostpath(pol, volume_name) = allowed {
    allowed := pol.spec.allowedHostPaths[_]
    hostPath := hostpath_volumes[volume_name].path
    path_matches(allowed.pathPrefix, hostPath)
}

# generates a set of volumes that have been mounted in write mode.
writeable_volume_mounts[volume_name] {
    container := input_containers[_]
    mount := container.volumeMounts[_]
    volume_name := mount.name
    not mount.readOnly
}

path_matches(prefix, path) {
    a := split(trim(prefix, "/"), "/")
    b := split(trim(path, "/"), "/")
    prefix_matches(a, b)
}

prefix_matches(a, b) {
    count(a) <= count(b)
    not any_not_equal_upto(a, b, count(a))
}

any_not_equal_upto(a, b, n) {
    a[i] != b[i]
    i < n
}

test_path_matches {
    path_matches("/foo", "/foo")
    path_matches("/foo", "/foo/bar")
    not path_matches("/foo/bar", "/foo")
    not path_matches("/fo", "/foo")
    not path_matches("/foobar", "/foo")
}

hostpath_volumes[name] = volume {
    some name
    volume := input.spec.volumes[name].hostPath
}