// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package engine

import (
	"errors"
	"os"
	"testing"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks_netns"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/execwrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper/mocks_fileinfo"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper/mocks_ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks_link"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	deviceName                = "eth1"
	firstENIID                = "eni1"
	secondENIID               = "eni2"
	firstMACAddress           = "mac1/"
	firstMACAddressSanitized  = "mac1"
	secondMACAddress          = "mac2/"
	secondMACAddressSanitized = "mac2"
	eniIPV4Address            = "10.11.12.13"
	eniIPV4Gateway            = "10.10.10.10"
	eniSubnetMask             = "20"
	eniIPV4CIDRBlock          = "10.10.10.10/20"
)

func setup(t *testing.T) (*gomock.Controller, *mock_ec2metadata.MockEC2Metadata, *mock_ioutilwrapper.MockIOUtil, *mock_cninswrapper.MockNS, *mock_netlinkwrapper.MockNetLink, *mock_execwrapper.MockExec) {
	ctrl := gomock.NewController(t)
	return ctrl, mock_ec2metadata.NewMockEC2Metadata(ctrl), mock_ioutilwrapper.NewMockIOUtil(ctrl), mock_cninswrapper.NewMockNS(ctrl), mock_netlinkwrapper.NewMockNetLink(ctrl), mock_execwrapper.NewMockExec(ctrl)
}

func TestCreate(t *testing.T) {
	ctrl, mockMetadata, mockIOUtil, mockNS, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	engine := create(mockMetadata, mockIOUtil, mockNetLink, mockNS, mockExec)
	assert.NotNil(t, engine)
}

func TestIsDHClientInPathReturnsFalseOnLookPathError(t *testing.T) {
	ctrl, _, _, _, _, mockExec := setup(t)
	defer ctrl.Finish()

	mockExec.EXPECT().LookPath(dhclientExecutableName).Return("", errors.New("error"))
	engine := &engine{exec: mockExec}

	ok := engine.IsDHClientInPath()
	assert.False(t, ok)
}

func TestIsDHClientInPath(t *testing.T) {
	ctrl, _, _, _, _, mockExec := setup(t)
	defer ctrl.Finish()

	mockExec.EXPECT().LookPath(dhclientExecutableName).Return("dhclient", nil)
	engine := &engine{exec: mockExec}

	ok := engine.IsDHClientInPath()
	assert.True(t, ok)
}

func TestGetAllMACAddressesReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetAllMACAddresses()
	assert.Error(t, err)
}

func TestGetAllMACAddresses(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("a\nb", nil)
	engine := &engine{metadata: mockMetadata}

	macs, err := engine.GetAllMACAddresses()
	assert.NoError(t, err)
	assert.NotEmpty(t, macs)
	assert.Len(t, macs, 2)
}

func TestGetMACAddressOfENIReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, firstENIID)
	assert.Error(t, err)
	_, ok := err.(*unmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENIReturnsErrorWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(firstENIID, nil)
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, secondENIID)
	assert.Error(t, err)
	_, ok := err.(*unmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENI(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(firstENIID, nil),
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+secondMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(secondENIID, nil),
	)
	engine := &engine{metadata: mockMetadata}

	addr, err := engine.GetMACAddressOfENI([]string{firstMACAddress, secondMACAddress}, secondENIID)
	assert.NoError(t, err)
	assert.Equal(t, addr, secondMACAddressSanitized)
}

func TestGetInterfaceDeviceNameReturnsErrorOnReadDirError(t *testing.T) {
	ctrl, _, mockIOUtil, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return(nil, errors.New("error"))
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*unmappedDeviceNameError)
	assert.False(t, ok)
}

func TestGetInterfaceDeviceNameReturnsErrorOnReadFileError(t *testing.T) {
	ctrl, _, mockIOUtil, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfo := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfo}, nil),
		mockFileInfo.EXPECT().Name().Return(deviceName),
		mockIOUtil.EXPECT().ReadFile(sysfsPathForNetworkDevices+deviceName+sysfsPathForNetworkDeviceAddressSuffix).Return(nil, errors.New("error")),
		mockFileInfo.EXPECT().Name().Return(deviceName),
	)
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*unmappedDeviceNameError)
	assert.True(t, ok)
}

func TestGetInterfaceDeviceNameReturnsErrorWhenDeviceNotFound(t *testing.T) {
	ctrl, _, mockIOUtil, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfo := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfo}, nil),
		mockFileInfo.EXPECT().Name().Return(deviceName),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+deviceName+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte(secondMACAddressSanitized), nil),
	)
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*unmappedDeviceNameError)
	assert.True(t, ok)
}

func TestGetInterfaceDeviceNameReturnsDeviceWhenFound(t *testing.T) {
	ctrl, _, mockIOUtil, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfoEth1 := mock_os.NewMockFileInfo(ctrl)
	mockFileInfoEth2 := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfoEth1, mockFileInfoEth2}, nil),
		mockFileInfoEth1.EXPECT().Name().Return(deviceName),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+deviceName+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte(firstMACAddressSanitized), nil),
		mockFileInfoEth2.EXPECT().Name().Return("eth2"),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+"eth2"+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte(secondMACAddressSanitized), nil),
		mockFileInfoEth2.EXPECT().Name().Return("eth2"),
	)
	engine := &engine{ioutil: mockIOUtil}

	deviceName, err := engine.GetInterfaceDeviceName(secondMACAddressSanitized)
	assert.NoError(t, err)
	assert.Equal(t, deviceName, "eth2")
}

func TestGetIPV4GatewayNetMaskLocalReturnsErrorOnMalformedCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskLocalReturnsErrorOnMalformedNetmaskInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.1/")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskLocalReturnsErrorOnMalformedCIDRBlockInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1/1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskLocalReturnsErrorOnEmptyRouterInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1./1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskLocalReturnsErrorOnInvalidRouterInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.foo/1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskLocal(t *testing.T) {
	gateway, netmask, err := getIPV4GatewayNetmask("10.0.1.64/26")
	assert.NoError(t, err)
	assert.Equal(t, gateway, "10.0.1.65")
	assert.Equal(t, netmask, "26")
}

func TestGetIPV4GatewayNetMaskReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("1.1.1.1", nil)
	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskWhenUnableToParseIPV6CIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("2001:db8::/32", nil)
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.True(t, ok)
}

func TestGetIPV4GatewayNetMask(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("172.31.32.0/20", nil)
	engine := &engine{metadata: mockMetadata}

	gateway, netmask, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.NoError(t, err)
	assert.Equal(t, "172.31.32.1", gateway)
	assert.Equal(t, "20", netmask)
}

func TestIsValidGetIPV4AddressReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.Error(t, err)
}

func TestDoesMACAddressMapToIPV4AddressReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return("172.31.32.3", nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestDoesMACAddressMapToIPV4AddressReturnsTrueWhenFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return(eniIPV4Address, nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestSetupContainerNamespaceFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnGetNSError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnLinksetNsFdError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnParseAddrError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnWithNetNSPathError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespace(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _ := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(nil),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
}

func TestNSClosureCreationFailsOnParseAddrError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(nil, errors.New("error"))
	_, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error")),
	)
	closure, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnAddrAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(errors.New("error")),
	)
	closure, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnLinkSetupError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(errors.New("error")),
	)
	closure, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestGetDHClientV4Args(t *testing.T) {
	args := getDHClientV4Args("eth1")
	assert.NotEmpty(t, args)
	assert.Equal(t, args,
		[]string{"-q",
			"-lf", dhclientV4LeaseFilePathPrefix + "-eth1.leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix + "-eth1.pid",
			"eth1"})
}

func TestNSClosureRunFailsODHClientV4ComandCombinedOutputError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, errors.New("error")),
	)
	closure, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRun(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
	)
	closure, err := newNSClosure(mockNetLink, mockExec, deviceName, eniIPV4Gateway, "20")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}
