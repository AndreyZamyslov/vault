// Code generated by sdkgen. DO NOT EDIT.

//nolint
package devices

import (
	"context"

	"google.golang.org/grpc"

	devices "github.com/yandex-cloud/go-genproto/yandex/cloud/iot/devices/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// RegistryServiceClient is a devices.RegistryServiceClient with
// lazy GRPC connection initialization.
type RegistryServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// AddCertificate implements devices.RegistryServiceClient
func (c *RegistryServiceClient) AddCertificate(ctx context.Context, in *devices.AddRegistryCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).AddCertificate(ctx, in, opts...)
}

// AddPassword implements devices.RegistryServiceClient
func (c *RegistryServiceClient) AddPassword(ctx context.Context, in *devices.AddRegistryPasswordRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).AddPassword(ctx, in, opts...)
}

// Create implements devices.RegistryServiceClient
func (c *RegistryServiceClient) Create(ctx context.Context, in *devices.CreateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).Create(ctx, in, opts...)
}

// Delete implements devices.RegistryServiceClient
func (c *RegistryServiceClient) Delete(ctx context.Context, in *devices.DeleteRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).Delete(ctx, in, opts...)
}

// DeleteCertificate implements devices.RegistryServiceClient
func (c *RegistryServiceClient) DeleteCertificate(ctx context.Context, in *devices.DeleteRegistryCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).DeleteCertificate(ctx, in, opts...)
}

// DeletePassword implements devices.RegistryServiceClient
func (c *RegistryServiceClient) DeletePassword(ctx context.Context, in *devices.DeleteRegistryPasswordRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).DeletePassword(ctx, in, opts...)
}

// Get implements devices.RegistryServiceClient
func (c *RegistryServiceClient) Get(ctx context.Context, in *devices.GetRegistryRequest, opts ...grpc.CallOption) (*devices.Registry, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).Get(ctx, in, opts...)
}

// List implements devices.RegistryServiceClient
func (c *RegistryServiceClient) List(ctx context.Context, in *devices.ListRegistriesRequest, opts ...grpc.CallOption) (*devices.ListRegistriesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).List(ctx, in, opts...)
}

type RegistryIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err     error
	started bool

	client  *RegistryServiceClient
	request *devices.ListRegistriesRequest

	items []*devices.Registry
}

func (c *RegistryServiceClient) RegistryIterator(ctx context.Context, folderId string, opts ...grpc.CallOption) *RegistryIterator {
	return &RegistryIterator{
		ctx:    ctx,
		opts:   opts,
		client: c,
		request: &devices.ListRegistriesRequest{
			FolderId: folderId,
			PageSize: 1000,
		},
	}
}

func (it *RegistryIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	response, err := it.client.List(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Registries
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *RegistryIterator) Value() *devices.Registry {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *RegistryIterator) Error() error {
	return it.err
}

// ListCertificates implements devices.RegistryServiceClient
func (c *RegistryServiceClient) ListCertificates(ctx context.Context, in *devices.ListRegistryCertificatesRequest, opts ...grpc.CallOption) (*devices.ListRegistryCertificatesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).ListCertificates(ctx, in, opts...)
}

type RegistryCertificatesIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err     error
	started bool

	client  *RegistryServiceClient
	request *devices.ListRegistryCertificatesRequest

	items []*devices.RegistryCertificate
}

func (c *RegistryServiceClient) RegistryCertificatesIterator(ctx context.Context, registryId string, opts ...grpc.CallOption) *RegistryCertificatesIterator {
	return &RegistryCertificatesIterator{
		ctx:    ctx,
		opts:   opts,
		client: c,
		request: &devices.ListRegistryCertificatesRequest{
			RegistryId: registryId,
		},
	}
}

func (it *RegistryCertificatesIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started {
		return false
	}
	it.started = true

	response, err := it.client.ListCertificates(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Certificates
	return len(it.items) > 0
}

func (it *RegistryCertificatesIterator) Value() *devices.RegistryCertificate {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *RegistryCertificatesIterator) Error() error {
	return it.err
}

// ListDeviceTopicAliases implements devices.RegistryServiceClient
func (c *RegistryServiceClient) ListDeviceTopicAliases(ctx context.Context, in *devices.ListDeviceTopicAliasesRequest, opts ...grpc.CallOption) (*devices.ListDeviceTopicAliasesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).ListDeviceTopicAliases(ctx, in, opts...)
}

type RegistryDeviceTopicAliasesIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err     error
	started bool

	client  *RegistryServiceClient
	request *devices.ListDeviceTopicAliasesRequest

	items []*devices.DeviceAlias
}

func (c *RegistryServiceClient) RegistryDeviceTopicAliasesIterator(ctx context.Context, registryId string, opts ...grpc.CallOption) *RegistryDeviceTopicAliasesIterator {
	return &RegistryDeviceTopicAliasesIterator{
		ctx:    ctx,
		opts:   opts,
		client: c,
		request: &devices.ListDeviceTopicAliasesRequest{
			RegistryId: registryId,
			PageSize:   1000,
		},
	}
}

func (it *RegistryDeviceTopicAliasesIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	response, err := it.client.ListDeviceTopicAliases(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Aliases
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *RegistryDeviceTopicAliasesIterator) Value() *devices.DeviceAlias {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *RegistryDeviceTopicAliasesIterator) Error() error {
	return it.err
}

// ListOperations implements devices.RegistryServiceClient
func (c *RegistryServiceClient) ListOperations(ctx context.Context, in *devices.ListRegistryOperationsRequest, opts ...grpc.CallOption) (*devices.ListRegistryOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).ListOperations(ctx, in, opts...)
}

type RegistryOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err     error
	started bool

	client  *RegistryServiceClient
	request *devices.ListRegistryOperationsRequest

	items []*operation.Operation
}

func (c *RegistryServiceClient) RegistryOperationsIterator(ctx context.Context, registryId string, opts ...grpc.CallOption) *RegistryOperationsIterator {
	return &RegistryOperationsIterator{
		ctx:    ctx,
		opts:   opts,
		client: c,
		request: &devices.ListRegistryOperationsRequest{
			RegistryId: registryId,
			PageSize:   1000,
		},
	}
}

func (it *RegistryOperationsIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	response, err := it.client.ListOperations(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Operations
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *RegistryOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *RegistryOperationsIterator) Error() error {
	return it.err
}

// ListPasswords implements devices.RegistryServiceClient
func (c *RegistryServiceClient) ListPasswords(ctx context.Context, in *devices.ListRegistryPasswordsRequest, opts ...grpc.CallOption) (*devices.ListRegistryPasswordsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).ListPasswords(ctx, in, opts...)
}

type RegistryPasswordsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err     error
	started bool

	client  *RegistryServiceClient
	request *devices.ListRegistryPasswordsRequest

	items []*devices.RegistryPassword
}

func (c *RegistryServiceClient) RegistryPasswordsIterator(ctx context.Context, registryId string, opts ...grpc.CallOption) *RegistryPasswordsIterator {
	return &RegistryPasswordsIterator{
		ctx:    ctx,
		opts:   opts,
		client: c,
		request: &devices.ListRegistryPasswordsRequest{
			RegistryId: registryId,
		},
	}
}

func (it *RegistryPasswordsIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started {
		return false
	}
	it.started = true

	response, err := it.client.ListPasswords(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Passwords
	return len(it.items) > 0
}

func (it *RegistryPasswordsIterator) Value() *devices.RegistryPassword {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *RegistryPasswordsIterator) Error() error {
	return it.err
}

// Update implements devices.RegistryServiceClient
func (c *RegistryServiceClient) Update(ctx context.Context, in *devices.UpdateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return devices.NewRegistryServiceClient(conn).Update(ctx, in, opts...)
}
