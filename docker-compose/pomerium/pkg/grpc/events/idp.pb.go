// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.14.0
// source: idp.proto

package events

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// IDPErrorEvents is a list of IDP error events.
type IDPErrorEvents struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Values []*IDPErrorEvent `protobuf:"bytes,1,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *IDPErrorEvents) Reset() {
	*x = IDPErrorEvents{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IDPErrorEvents) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IDPErrorEvents) ProtoMessage() {}

func (x *IDPErrorEvents) ProtoReflect() protoreflect.Message {
	mi := &file_idp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IDPErrorEvents.ProtoReflect.Descriptor instead.
func (*IDPErrorEvents) Descriptor() ([]byte, []int) {
	return file_idp_proto_rawDescGZIP(), []int{0}
}

func (x *IDPErrorEvents) GetValues() []*IDPErrorEvent {
	if x != nil {
		return x.Values
	}
	return nil
}

// IDPErrorEvent is an IDP error event.
type IDPErrorEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Time    *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=time,proto3" json:"time,omitempty"`
	Message string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *IDPErrorEvent) Reset() {
	*x = IDPErrorEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idp_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IDPErrorEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IDPErrorEvent) ProtoMessage() {}

func (x *IDPErrorEvent) ProtoReflect() protoreflect.Message {
	mi := &file_idp_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IDPErrorEvent.ProtoReflect.Descriptor instead.
func (*IDPErrorEvent) Descriptor() ([]byte, []int) {
	return file_idp_proto_rawDescGZIP(), []int{1}
}

func (x *IDPErrorEvent) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *IDPErrorEvent) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_idp_proto protoreflect.FileDescriptor

var file_idp_proto_rawDesc = []byte{
	0x0a, 0x09, 0x69, 0x64, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x70, 0x6f, 0x6d,
	0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x48, 0x0a,
	0x0e, 0x49, 0x44, 0x50, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x12,
	0x36, 0x0a, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x73, 0x2e, 0x49, 0x44, 0x50, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52,
	0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x59, 0x0a, 0x0d, 0x49, 0x44, 0x50, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69,
	0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_idp_proto_rawDescOnce sync.Once
	file_idp_proto_rawDescData = file_idp_proto_rawDesc
)

func file_idp_proto_rawDescGZIP() []byte {
	file_idp_proto_rawDescOnce.Do(func() {
		file_idp_proto_rawDescData = protoimpl.X.CompressGZIP(file_idp_proto_rawDescData)
	})
	return file_idp_proto_rawDescData
}

var file_idp_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_idp_proto_goTypes = []interface{}{
	(*IDPErrorEvents)(nil),        // 0: pomerium.events.IDPErrorEvents
	(*IDPErrorEvent)(nil),         // 1: pomerium.events.IDPErrorEvent
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_idp_proto_depIdxs = []int32{
	1, // 0: pomerium.events.IDPErrorEvents.values:type_name -> pomerium.events.IDPErrorEvent
	2, // 1: pomerium.events.IDPErrorEvent.time:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_idp_proto_init() }
func file_idp_proto_init() {
	if File_idp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_idp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IDPErrorEvents); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_idp_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IDPErrorEvent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_idp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_idp_proto_goTypes,
		DependencyIndexes: file_idp_proto_depIdxs,
		MessageInfos:      file_idp_proto_msgTypes,
	}.Build()
	File_idp_proto = out.File
	file_idp_proto_rawDesc = nil
	file_idp_proto_goTypes = nil
	file_idp_proto_depIdxs = nil
}
