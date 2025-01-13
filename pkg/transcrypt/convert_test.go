package transcrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/minio/sio"
)

func Test_convertBytesToValue_String(t *testing.T) {
	type args struct {
		d []byte
		k reflect.Kind
	}

	tests := []struct {
		name    string
		args    args
		want    reflect.Value
		wantErr bool
	}{
		{
			name: "string",
			args: args{
				d: []byte("hello world"),
				k: reflect.TypeOf("hello world").Kind(),
			},
			want:    reflect.ValueOf("hello world"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertBytesToValue(tt.args.d, tt.args.k)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertBytesToValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.String(), tt.want.String()) {
				t.Errorf("convertBytesToValue() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_convertBytesToValue_Uint(t *testing.T) {
	type args struct {
		d []byte
		k reflect.Kind
	}
	var inputUint uint64 = 132130
	bufWriterUint := bytes.NewBuffer(make([]byte, 0))
	if bufErr := binary.Write(bufWriterUint, binary.BigEndian, inputUint); bufErr != nil {
		panic(bufErr)
	}

	var inputInt = 132130
	bufWriterInt := bytes.NewBuffer(make([]byte, 0))
	if bufErr := binary.Write(bufWriterInt, binary.BigEndian, int64(inputInt)); bufErr != nil {
		panic(bufErr)
	}
	tests := []struct {
		name    string
		args    args
		want    reflect.Value
		wantErr bool
	}{
		{
			name: "uint64",
			args: args{
				d: bufWriterUint.Bytes(),
				k: reflect.TypeOf(inputUint).Kind(),
			},
			want:    reflect.ValueOf(inputUint),
			wantErr: false,
		},
		{
			name: "int64",
			args: args{
				d: bufWriterInt.Bytes(),
				k: reflect.TypeOf(inputInt).Kind(),
			},
			want:    reflect.ValueOf(inputInt),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertBytesToValue(tt.args.d, tt.args.k)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertBytesToValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == tt.want {
				t.Errorf("convertBytesToValue() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_convertValueToHexString(t *testing.T) {
	type args struct {
		v reflect.Value
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "string",
			args: args{
				v: reflect.ValueOf("hello world"),
			},
			want:    "68656c6c6f20776f726c64",
			wantErr: false,
		},
		{
			name: "int",
			args: args{
				v: reflect.ValueOf(132130),
			},
			want:    "0000000000020422",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertValueToHexString(tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertValueToHexString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("convertValueToHexString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeHexString(t *testing.T) {
	type args struct {
		key  string
		data string
	}

	decodedHexKey, _ := hex.DecodeString("308204a20201000282010100b44756063cdb25f2e5ec868ecc5edc733896d637f5e0ffd8a3f820fb0f2acb2268c69a7774c2d4c4ede1ec47d894bbb0f928e9e700db03767b6152548c49f3170d011dd87aa3d36a1f49d38756bcbc6e122d362ff3986165985d264f11ba8e1d35006b66290c4efa8dfd6b4bcbb5e3fbf9277d31ffaa09b319a976313c3bcd25f3b74be78df293bd7b38e5a6caf48be79684882af47630eb147ecb4426e9e7e6e9554b1d8b53530c5c22cfe44e95bfeeca4bb79f1a3c08e5de93d3bf458aae5e821e9e6c4ec6c3602b9b1f56b31da14775608374ec8653e34e2025901cbef725241b166187972dc1c1913f2c8ba54f1ceb443b4019096fac816cf6334aa2e3f50203010001028201004703b2c75241a17945491ed831794cadb6a4f44da6f5b2d2cc047a396b8817ecbe093ddfc086def9941b62d00a68cc66b23f83a4139a328b019f1ca7617bdfde3ca92bf0929ee630ef924d590ab9de201dd8e17792257c7860c490caa4d930122146c107c533ac08d6d5f4e62ea0bfe60a079c318ddc95658fbe4968aba982edbe0775e71eba35836758b2c486e54e54de4cbb3b7004a9e16b0d0da3b88dbf026413d97e0396aec1f739d504b4eb75a7719fb7bda9886c78a99a79a55ad2b06c36a46ac6df71cd021296020865a2f79b3a0950f9268a1fc773ab407e3e283c10f6fe9412acbae260c2a5c601d75a731db18294a91d20cce7d73d039d7162742102818100efad47d757feb7f570f55f81b7b0fe271de91633234146b5f9fb682b3aafd574481bbd49c85b27c4c118f2634755800b4eb967e46ff6ca4f392bac226410ce31b7c0d22735e61928a940d36033aac6aaa088d21a36720b90904a7ea8b62f998a99938d5ced7b8f2eb2339e34559b25506c43bed054562543a260f426c3136ac702818100c08e75852d7375a09087a5e793d7372e3804257dda911408a1270a14a825879e26d5c7b85796a5ff6f4a290a9185cc097d3eebe0bb2fd8520b50cc9f4bb30a7815a51a23d5ea752f8035c242bce5839ad4f4c6fcb5921e1a8a8f672fc378a7afc57a04c2e882c21414c656b84bf8c3efd4ea0dbbd4269e048e66196d57b99f630281807f592ce0e8ea78c83afac582611df40cc8c1be7ff16d8faac566a5d4c25c0728bfdfad55f4d52a6e4ac37c96efa22864d9b17dd84cfd6e4565f5248329741c7b224d9bdc25b15b10d5cd92027db171d9db6e976442259aab775f7da91b14739ac73b35537903bbf26dd12b7057441631833503c021ef9be131f81e023288b0a50281807cc552bd4320479e0d48f865c0547a3b06ad19261dd45828e75386a2aff9f190b7155b5ec5d2a629881183da87452d5b10bf0ed506361073c94547f20879315572a112f91989dcf93498a111e198ced82b19993ef2e08585293796e34a440a54491fb1aa22436842dedb4e2209885e5e2f96a1e38daaa045cf87b4fe3713de8502818021680ea1a93b048af3deec6fd09d9d110d391e908cb6eeab615e5595556f07238c44f7b8795cffe3508aa3dff21de927576454537473e9b07eaedf0864f4a5a0f6275fbef3f6c9b42f7c692b351451004c25c4918edabbd1f22e5d174aac550db7327e99cb58be7641ec0479425bf00f8b3640685a95e70c93e820c7f39e1a1e")
	tests := []struct {
		name       string
		args       args
		wantData   []byte
		wantKind   reflect.Kind
		wantConfig sio.Config
		wantErr    bool
	}{
		{
			name: "empty_key",
			args: args{
				key:  "",
				data: "",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "empty_data",
			args: args{
				key:  string(decodedHexKey),
				data: "",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "invalid_value_ciphersuite",
			args: args{
				key:  string(decodedHexKey),
				data: "__:68e191dfc1f3180904d19a58:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "invalid_value_nonce",
			args: args{
				key:  string(decodedHexKey),
				data: "00:__:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "invalid_value_data",
			args: args{
				key:  string(decodedHexKey),
				data: "00:68e191dfc1f3180904d19a58:__:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "invalid_value_kind",
			args: args{
				key:  string(decodedHexKey),
				data: "00:68e191dfc1f3180904d19a58:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:__",
			},
			wantData: nil,
			wantKind: reflect.Invalid,
			wantErr:  true,
		},
		{
			name: "invalid_ciphersuite",
			args: args{
				key:  string(decodedHexKey),
				data: "dd:68e191dfc1f3180904d19a58:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.String,
			wantErr:  true,
		},
		{
			name: "invalid_nonce",
			args: args{
				key:  string(decodedHexKey),
				data: "00:dddddddddddddddddddddddd:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.String,
			wantErr:  true,
		},
		{
			name: "invalid_data",
			args: args{
				key:  string(decodedHexKey),
				data: "00:68e191dfc1f3180904d19a58:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.String,
			wantErr:  true,
		},
		{
			name: "invalid_kind",
			args: args{
				key:  string(decodedHexKey),
				data: "00:68e191dfc1f3180904d19a58:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:dddddddddddd",
			},
			wantData: nil,
			wantKind: reflect.String,
			wantErr:  true,
		},
		{
			name: "valid",
			args: args{
				key:  string(decodedHexKey),
				data: "00:68e191dfc1f3180904d19a58:20001500e8e191dfc1f3180904d19a589d6c41d057473145672f5e7a90b1fa1d47b21ece952eafbbfa38668f2885b323179721bc10a5:737472696e67",
			},
			wantData: nil,
			wantKind: reflect.String,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, gotKind, gotConfig, err := decodeHexString(tt.args.key, tt.args.data)
			if err != nil {
				if (err != nil) != tt.wantErr {
					t.Errorf("decodeHexString() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if string(gotData) == string(tt.wantData) {
				t.Errorf("decodeHexString() gotData = %v, wantData %v", gotData, tt.wantData)
			}
			if gotKind != tt.wantKind {
				t.Errorf("decodeHexString() gotKind = %v, wantKind %v", gotKind, tt.wantKind)
			}
			if string(gotConfig.CipherSuites) == string(tt.wantConfig.CipherSuites) {
				t.Errorf("decodeHexString() gotCipherSuites = %v, wantCipherSuites %v", gotConfig, tt.wantConfig)
			}
		})
	}
}
