//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// restrictToOwner applies an explicit owner-only protected DACL to path
// (file or directory). POSIX modes passed to os.OpenFile do NOT map to a
// Windows ACL, so without this the durable log would inherit the
// profile default instead of the per-user guarantee we claim
// (audit point 4). Errors are returned; callers log and continue.
func restrictToOwner(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
