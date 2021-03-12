// Code generated by protoc-gen-go. DO NOT EDIT.
// source: yandex/cloud/marketplace/v1/metering/usage_record.proto

package metering

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	_ "github.com/yandex-cloud/go-genproto/yandex/cloud"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type RejectedUsageRecord_Reason int32

const (
	RejectedUsageRecord_REASON_UNSPECIFIED RejectedUsageRecord_Reason = 0
	RejectedUsageRecord_DUPLICATE          RejectedUsageRecord_Reason = 1
	RejectedUsageRecord_EXPIRED            RejectedUsageRecord_Reason = 2
	RejectedUsageRecord_INVALID_TIMESTAMP  RejectedUsageRecord_Reason = 3
	RejectedUsageRecord_INVALID_SKU_ID     RejectedUsageRecord_Reason = 4
	RejectedUsageRecord_INVALID_PRODUCT_ID RejectedUsageRecord_Reason = 5
	RejectedUsageRecord_INVALID_QUANTITY   RejectedUsageRecord_Reason = 6
	RejectedUsageRecord_INVALID_ID         RejectedUsageRecord_Reason = 7
)

var RejectedUsageRecord_Reason_name = map[int32]string{
	0: "REASON_UNSPECIFIED",
	1: "DUPLICATE",
	2: "EXPIRED",
	3: "INVALID_TIMESTAMP",
	4: "INVALID_SKU_ID",
	5: "INVALID_PRODUCT_ID",
	6: "INVALID_QUANTITY",
	7: "INVALID_ID",
}

var RejectedUsageRecord_Reason_value = map[string]int32{
	"REASON_UNSPECIFIED": 0,
	"DUPLICATE":          1,
	"EXPIRED":            2,
	"INVALID_TIMESTAMP":  3,
	"INVALID_SKU_ID":     4,
	"INVALID_PRODUCT_ID": 5,
	"INVALID_QUANTITY":   6,
	"INVALID_ID":         7,
}

func (x RejectedUsageRecord_Reason) String() string {
	return proto.EnumName(RejectedUsageRecord_Reason_name, int32(x))
}

func (RejectedUsageRecord_Reason) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ed020edab63683f5, []int{2, 0}
}

type UsageRecord struct {
	// Unique identitifier of the usage record (UUID format)
	Uuid string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	// Consumed Marketplace SaaS Sku ID, linked to `UsageRecord.product_id`
	SkuId string `protobuf:"bytes,2,opt,name=sku_id,json=skuId,proto3" json:"sku_id,omitempty"`
	// Quantity of sku consumed, measured in `sku.usage_unit` units (e.g. bytes)
	Quantity int64 `protobuf:"varint,3,opt,name=quantity,proto3" json:"quantity,omitempty"`
	// Timestamp in UTC for which the usage is being reported
	Timestamp            *timestamp.Timestamp `protobuf:"bytes,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *UsageRecord) Reset()         { *m = UsageRecord{} }
func (m *UsageRecord) String() string { return proto.CompactTextString(m) }
func (*UsageRecord) ProtoMessage()    {}
func (*UsageRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed020edab63683f5, []int{0}
}

func (m *UsageRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UsageRecord.Unmarshal(m, b)
}
func (m *UsageRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UsageRecord.Marshal(b, m, deterministic)
}
func (m *UsageRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UsageRecord.Merge(m, src)
}
func (m *UsageRecord) XXX_Size() int {
	return xxx_messageInfo_UsageRecord.Size(m)
}
func (m *UsageRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_UsageRecord.DiscardUnknown(m)
}

var xxx_messageInfo_UsageRecord proto.InternalMessageInfo

func (m *UsageRecord) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

func (m *UsageRecord) GetSkuId() string {
	if m != nil {
		return m.SkuId
	}
	return ""
}

func (m *UsageRecord) GetQuantity() int64 {
	if m != nil {
		return m.Quantity
	}
	return 0
}

func (m *UsageRecord) GetTimestamp() *timestamp.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

type AcceptedUsageRecord struct {
	// Unique identitifier of the usage record (UUID format)
	Uuid                 string   `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AcceptedUsageRecord) Reset()         { *m = AcceptedUsageRecord{} }
func (m *AcceptedUsageRecord) String() string { return proto.CompactTextString(m) }
func (*AcceptedUsageRecord) ProtoMessage()    {}
func (*AcceptedUsageRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed020edab63683f5, []int{1}
}

func (m *AcceptedUsageRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AcceptedUsageRecord.Unmarshal(m, b)
}
func (m *AcceptedUsageRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AcceptedUsageRecord.Marshal(b, m, deterministic)
}
func (m *AcceptedUsageRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AcceptedUsageRecord.Merge(m, src)
}
func (m *AcceptedUsageRecord) XXX_Size() int {
	return xxx_messageInfo_AcceptedUsageRecord.Size(m)
}
func (m *AcceptedUsageRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_AcceptedUsageRecord.DiscardUnknown(m)
}

var xxx_messageInfo_AcceptedUsageRecord proto.InternalMessageInfo

func (m *AcceptedUsageRecord) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

type RejectedUsageRecord struct {
	// Unique identitifier of the usage record (UUID format)
	Uuid string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	// The reason of rejection
	Reason               RejectedUsageRecord_Reason `protobuf:"varint,2,opt,name=reason,proto3,enum=yandex.cloud.marketplace.v1.metering.RejectedUsageRecord_Reason" json:"reason,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *RejectedUsageRecord) Reset()         { *m = RejectedUsageRecord{} }
func (m *RejectedUsageRecord) String() string { return proto.CompactTextString(m) }
func (*RejectedUsageRecord) ProtoMessage()    {}
func (*RejectedUsageRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed020edab63683f5, []int{2}
}

func (m *RejectedUsageRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RejectedUsageRecord.Unmarshal(m, b)
}
func (m *RejectedUsageRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RejectedUsageRecord.Marshal(b, m, deterministic)
}
func (m *RejectedUsageRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RejectedUsageRecord.Merge(m, src)
}
func (m *RejectedUsageRecord) XXX_Size() int {
	return xxx_messageInfo_RejectedUsageRecord.Size(m)
}
func (m *RejectedUsageRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_RejectedUsageRecord.DiscardUnknown(m)
}

var xxx_messageInfo_RejectedUsageRecord proto.InternalMessageInfo

func (m *RejectedUsageRecord) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

func (m *RejectedUsageRecord) GetReason() RejectedUsageRecord_Reason {
	if m != nil {
		return m.Reason
	}
	return RejectedUsageRecord_REASON_UNSPECIFIED
}

func init() {
	proto.RegisterEnum("yandex.cloud.marketplace.v1.metering.RejectedUsageRecord_Reason", RejectedUsageRecord_Reason_name, RejectedUsageRecord_Reason_value)
	proto.RegisterType((*UsageRecord)(nil), "yandex.cloud.marketplace.v1.metering.UsageRecord")
	proto.RegisterType((*AcceptedUsageRecord)(nil), "yandex.cloud.marketplace.v1.metering.AcceptedUsageRecord")
	proto.RegisterType((*RejectedUsageRecord)(nil), "yandex.cloud.marketplace.v1.metering.RejectedUsageRecord")
}

func init() {
	proto.RegisterFile("yandex/cloud/marketplace/v1/metering/usage_record.proto", fileDescriptor_ed020edab63683f5)
}

var fileDescriptor_ed020edab63683f5 = []byte{
	// 512 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x53, 0xd1, 0x6e, 0xd3, 0x3c,
	0x18, 0xfd, 0xd3, 0x76, 0xd9, 0x5f, 0x17, 0xaa, 0xe0, 0x01, 0xaa, 0x2a, 0x10, 0x55, 0xe1, 0xa2,
	0x5c, 0xcc, 0x5e, 0x37, 0x01, 0x17, 0xc0, 0x44, 0xda, 0x04, 0xc9, 0x62, 0xeb, 0x3a, 0x37, 0x41,
	0x83, 0x9b, 0xca, 0x4d, 0x4c, 0x30, 0x6d, 0xe3, 0x90, 0x38, 0x15, 0xbb, 0xe0, 0x05, 0x78, 0x0f,
	0xae, 0x78, 0x01, 0xde, 0x60, 0x3c, 0x0a, 0xcf, 0xc0, 0x15, 0x6a, 0xd2, 0x8c, 0x0e, 0x81, 0xd8,
	0x5d, 0x72, 0xbe, 0x73, 0x8e, 0xcf, 0xd1, 0x67, 0x83, 0x47, 0xa7, 0x2c, 0xf4, 0xf9, 0x07, 0xec,
	0xcd, 0x64, 0xea, 0xe3, 0x39, 0x8b, 0xa7, 0x5c, 0x45, 0x33, 0xe6, 0x71, 0xbc, 0xe8, 0xe2, 0x39,
	0x57, 0x3c, 0x16, 0x61, 0x80, 0xd3, 0x84, 0x05, 0x7c, 0x1c, 0x73, 0x4f, 0xc6, 0x3e, 0x8a, 0x62,
	0xa9, 0x24, 0xbc, 0x97, 0x0b, 0x51, 0x26, 0x44, 0x6b, 0x42, 0xb4, 0xe8, 0xa2, 0x42, 0xd8, 0xbc,
	0x15, 0x48, 0x19, 0xcc, 0x38, 0x66, 0x91, 0xc0, 0x2c, 0x0c, 0xa5, 0x62, 0x4a, 0xc8, 0x30, 0xc9,
	0x3d, 0x9a, 0x77, 0x56, 0xd3, 0xec, 0x6f, 0x92, 0xbe, 0xc1, 0x4a, 0xcc, 0x79, 0xa2, 0xd8, 0x3c,
	0x5a, 0x11, 0x6e, 0x5f, 0x48, 0xb7, 0x60, 0x33, 0xe1, 0x67, 0x06, 0xf9, 0xb8, 0xfd, 0x55, 0x03,
	0x35, 0x77, 0x19, 0x8d, 0x66, 0xc9, 0x60, 0x0b, 0x54, 0xd2, 0x54, 0xf8, 0x0d, 0xad, 0xa5, 0x75,
	0xaa, 0xbd, 0x2b, 0xdf, 0xcf, 0xba, 0xda, 0xa7, 0x6f, 0xdd, 0xca, 0x93, 0xa7, 0x7b, 0x0f, 0x69,
	0x36, 0x81, 0x77, 0x81, 0x9e, 0x4c, 0xd3, 0xb1, 0xf0, 0x1b, 0xa5, 0xdf, 0x39, 0x0f, 0x76, 0xe8,
	0x46, 0x32, 0x4d, 0x89, 0x0f, 0xdb, 0xe0, 0xff, 0xf7, 0x29, 0x0b, 0x95, 0x50, 0xa7, 0x8d, 0x72,
	0x4b, 0xeb, 0x94, 0x7b, 0xfa, 0x8f, 0xb3, 0x6e, 0x69, 0x7f, 0x87, 0x9e, 0xe3, 0x70, 0x1f, 0x54,
	0xcf, 0xc3, 0x36, 0x2a, 0x2d, 0xad, 0x53, 0xdb, 0x6d, 0xa2, 0xbc, 0x0e, 0x2a, 0xea, 0x20, 0xa7,
	0x60, 0xf4, 0x2a, 0xcb, 0x73, 0xe8, 0x2f, 0x49, 0xfb, 0x3e, 0xd8, 0x32, 0x3d, 0x8f, 0x47, 0x8a,
	0xfb, 0xeb, 0x0d, 0xe0, 0x7a, 0x83, 0x3c, 0x73, 0xfb, 0x4b, 0x09, 0x6c, 0x51, 0xfe, 0x8e, 0x7b,
	0xff, 0xe6, 0xc2, 0x13, 0xa0, 0xc7, 0x9c, 0x25, 0x32, 0xcc, 0xfa, 0xd5, 0x77, 0x9f, 0xa1, 0xcb,
	0xac, 0x09, 0xfd, 0xc1, 0x1e, 0xd1, 0xcc, 0x87, 0xae, 0xfc, 0xda, 0x9f, 0x35, 0xa0, 0xe7, 0x10,
	0xbc, 0x09, 0x20, 0xb5, 0xcd, 0xd1, 0xd1, 0x60, 0xec, 0x0e, 0x46, 0x43, 0xbb, 0x4f, 0x9e, 0x13,
	0xdb, 0x32, 0xfe, 0x83, 0x57, 0x41, 0xd5, 0x72, 0x87, 0x07, 0xa4, 0x6f, 0x3a, 0xb6, 0xa1, 0xc1,
	0x1a, 0xd8, 0xb4, 0x4f, 0x86, 0x84, 0xda, 0x96, 0x51, 0x82, 0x37, 0xc0, 0x35, 0x32, 0x78, 0x69,
	0x1e, 0x10, 0x6b, 0xec, 0x90, 0x43, 0x7b, 0xe4, 0x98, 0x87, 0x43, 0xa3, 0x0c, 0x21, 0xa8, 0x17,
	0xf0, 0xe8, 0x85, 0x3b, 0x26, 0x96, 0x51, 0x59, 0xda, 0x17, 0xd8, 0x90, 0x1e, 0x59, 0x6e, 0xdf,
	0x59, 0xe2, 0x1b, 0xf0, 0x3a, 0x30, 0x0a, 0xfc, 0xd8, 0x35, 0x07, 0x0e, 0x71, 0x5e, 0x19, 0x3a,
	0xac, 0x03, 0x50, 0xa0, 0xc4, 0x32, 0x36, 0x7b, 0x1f, 0x41, 0xe7, 0x42, 0x65, 0x16, 0x89, 0xbf,
	0xd5, 0x7e, 0x7d, 0x1c, 0x08, 0xf5, 0x36, 0x9d, 0x20, 0x4f, 0xce, 0x71, 0x2e, 0xda, 0xce, 0x6f,
	0x5a, 0x20, 0xb7, 0x03, 0x1e, 0x66, 0x7b, 0xc4, 0x97, 0x79, 0x20, 0x8f, 0x8b, 0x8f, 0x89, 0x9e,
	0x89, 0xf6, 0x7e, 0x06, 0x00, 0x00, 0xff, 0xff, 0x6b, 0x49, 0x6b, 0x91, 0x58, 0x03, 0x00, 0x00,
}
