package psp

violations[name] {
    some name
    flexvolume_violation[name]
}

flexvolume_violation[name] {
    some name, volume_name
    pol := psps[name]
    driver := input.spec.volumes[volume_name].flexVolume.driver
    not flex_driver_allowed(pol, driver)
}

flex_driver_allowed(pol, _) {
    pol.spec.allowedFlexDrivers == []
}

flex_driver_allowed(pol, driver) {
     pol.spec.allowedFlexDrivers[_] == driver
}

