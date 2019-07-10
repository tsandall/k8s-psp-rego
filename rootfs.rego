package psp

violations[psp] {
    some psp
    readonly_rootfs_violation[psp]
}

readonly_rootfs_violation[name] {
    some name, container
    psps[name].spec.readOnlyRootFilesystem
    input_containers[container]
    not container.securityContext.readOnlyRootFilesystem
}