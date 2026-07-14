//go:build js || plan9 || wasip1

package host

func isConnectionRefused(_ error) bool { return false }

func isConnectionAborted(_ error) bool { return false }

func isConnectionReset(_ error) bool { return false }

func isNotConnected(_ error) bool { return false }
