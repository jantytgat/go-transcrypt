package transcrypt

import "testing"

func TestGetCipherSuite(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    CipherSuite
		wantErr bool
	}{
		{
			name: "AES_256_GCM",
			args: args{s: "AES_256_GCM"},
			want: AES_256_GCM,
		},
		{
			name: "CHACHA20_POLY1305",
			args: args{s: "CHACHA20_POLY1305"},
			want: CHACHA20_POLY1305,
		},
		{
			name:    "unknown",
			args:    args{s: "random"},
			wantErr: true,
		},
		{
			name:    "empty",
			args:    args{s: ""},
			wantErr: true,
		},
		{
			name:    "wrong_case",
			args:    args{s: "aes_256_gcm"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetCipherSuite(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCipherSuite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("GetCipherSuite() = %v, want %v", got, tt.want)
			}
		})
	}
}
