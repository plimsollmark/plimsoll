package sandbox

import "net"

func dialUnix(path string) (net.Conn, error) { return net.Dial("unix", path) }
