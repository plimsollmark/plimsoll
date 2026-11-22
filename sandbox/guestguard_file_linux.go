package sandbox

import "syscall"

// statfs's f_flags bits (linux/statfs.h): ST_NOEXEC is the noexec mount option; ST_VALID says
// the kernel filled the flags in (every kernel since 2.6.36).
const (
	stNoExec = 0x0008
	stValid  = 0x0020
)

// guestGuardFolderNoExec reports whether dir's filesystem is mounted noexec.
var guestGuardFolderNoExec = func(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	if st.Flags&stValid == 0 {
		return false, syscall.ENOTSUP
	}
	return st.Flags&stNoExec != 0, nil
}
