package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInvalidIPAddress tests invalid IP address will cause error
func TestInvalidIPAddress(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"subnet": "10.0.0.0/24",
				"ipAddress": "%s"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0")), "")
	assert.Error(t, err, "expect error for invalid ip address")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0.1")), "")
	assert.Error(t, err, "expect error for missing mask in ipaddress")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0.2/24")), "")
	assert.NoError(t, err, "valid ip address should cause loading configuration error")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "")), "")
	assert.Error(t, err, "expect error for missing IP address in the configuration")
}

// TestEmptySubnentGw tests missing both subnent and gateway will cause error
func TestEmptySubnentGw(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipAddress": "10.0.0.2/24"
			}
		}`

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}

	err := cmdAdd(args)
	assert.Error(t, err, "expect error for missing both subnent and gateway in configuration")
}

// TestDefaultGw tests the default gateway will be given if gateway is not specified
func TestDefaultGw(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipAddress": "10.0.0.2/24",
				"subnet": "10.0.0.0/24"
			}
		}`

	// redirect the stdout to capture the returned output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "expect redirect os.stdin succeed")

	os.Stdout = w

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}
	err = cmdAdd(args)
	assert.NoError(t, err, "expect no error")

	w.Close()
	output, err := ioutil.ReadAll(r)

	os.Stdout = oldStdout
	require.NoError(t, err, "expect reading from stdin succeed")

	res, err := version.NewResult("0.3.0", output)
	require.NoError(t, err, "")

	result, err := current.GetResult(res)
	require.NoError(t, err, "expect the result has correct format")

	assert.Equal(t, result.IPs[0].Gateway, net.ParseIP("10.0.0.1"), "expect to set the first address as default gateway")
}

func TestIPv4HappyPath(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipAddress": "10.0.0.2/24",
				"gateway": "10.0.0.8",
				"routes": [
				{"dst": "192.168.2.3/32"}
				]
			}
		}`

	// redirect the stdout to capture the returned output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "expect redirect os.stdin succeed")

	os.Stdout = w

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}
	err = cmdAdd(args)
	assert.NoError(t, err, "expect no error")
	w.Close()

	output, err := ioutil.ReadAll(r)
	os.Stdout = oldStdout
	require.NoError(t, err, "expect reading from stdin succeed")

	res, _ := version.NewResult("0.3.0", output)
	result, err := current.GetResult(res)
	require.NoError(t, err, "expect the result has correct format")

	assert.Equal(t, result.IPs[0].Gateway, net.ParseIP("10.0.0.8"), "result should be same as configured")
	assert.Equal(t, result.IPs[0].Address.IP, net.ParseIP("10.0.0.2"), "result should be same as configured")
	assert.Equal(t, result.Routes[0].Dst.String(), "192.168.2.3/32", "result should be same as configured")
}

func TestIPv6HappyPath(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipAddress": "3ffe:ffff:0:01ff::0010/60",
				"subnet": "3ffe:ffff:0:01ff::/60",
				"routes": [
				{"dst": "fe:f:0:0::3/64", "gw": "3ffe:ffff:0:01ff::1"}
				]
			}
		}`

	// redirect the stdout to capture the returned output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "expect redirect os.stdin succeed")

	os.Stdout = w

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}
	err = cmdAdd(args)
	assert.NoError(t, err, "expect no error")
	w.Close()
	output, err := ioutil.ReadAll(r)
	os.Stdout = oldStdout
	require.NoError(t, err, "expect reading from stdin succeed")

	res, _ := version.NewResult("0.3.0", output)
	result, err := current.GetResult(res)
	require.NoError(t, err, "expect the result has correct format")

	assert.Equal(t, result.IPs[0].Gateway, net.ParseIP("3ffe:ffff:0:01ff::1"), "result should be same as configured")
	assert.Equal(t, result.IPs[0].Address.IP, net.ParseIP("3ffe:ffff:0:01ff::0010"), "result should be same as configured")

	expectedIP, expectedRouteDst, _ := net.ParseCIDR("fe:f:0:0::3/64")
	assert.Equal(t, result.Routes[0].Dst.IP, expectedIP, "result should be same as configured")
	assert.Equal(t, result.Routes[0].Dst.Mask, expectedRouteDst.Mask, "result should be same as configured")
	assert.Equal(t, result.Routes[0].GW, net.ParseIP("3ffe:ffff:0:01ff::1"), "result should be same as configured")
}
