//go:build !vrdev

package cmd

// devMemberHold is the development readiness hold of the vrdev build; a production build has none.
func devMemberHold(string) func() bool { return nil }
