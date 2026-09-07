package xfrm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestAddOrReplaceXFRMStateReplacesCollision(t *testing.T) {
	originalAdd, originalDel := xfrmStateAdd, xfrmStateDel
	t.Cleanup(func() {
		xfrmStateAdd, xfrmStateDel = originalAdd, originalDel
	})

	addCalls, deleteCalls := 0, 0
	xfrmStateAdd = func(*netlink.XfrmState) error {
		addCalls++
		if addCalls == 1 {
			return unix.EEXIST
		}
		return nil
	}
	xfrmStateDel = func(*netlink.XfrmState) error {
		deleteCalls++
		return nil
	}

	require.NoError(t, addOrReplaceXFRMState(&netlink.XfrmState{}))
	require.Equal(t, 2, addCalls)
	require.Equal(t, 1, deleteCalls)
}

func TestAddOrReplaceXFRMPolicyReplacesCollision(t *testing.T) {
	originalAdd, originalDel := xfrmPolicyAdd, xfrmPolicyDel
	t.Cleanup(func() {
		xfrmPolicyAdd, xfrmPolicyDel = originalAdd, originalDel
	})

	addCalls, deleteCalls := 0, 0
	xfrmPolicyAdd = func(*netlink.XfrmPolicy) error {
		addCalls++
		if addCalls == 1 {
			return unix.EEXIST
		}
		return nil
	}
	xfrmPolicyDel = func(*netlink.XfrmPolicy) error {
		deleteCalls++
		return nil
	}

	require.NoError(t, addOrReplaceXFRMPolicy(&netlink.XfrmPolicy{}))
	require.Equal(t, 2, addCalls)
	require.Equal(t, 1, deleteCalls)
}
