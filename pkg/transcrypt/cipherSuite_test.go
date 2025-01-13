package transcrypt

import "testing"

func TestGetCipherSuite(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want CipherSuite
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
			name: "random",
			args: args{s: "random"},
			want: CHACHA20_POLY1305,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCipherSuite(tt.args.s); got != tt.want {
				t.Errorf("GetCipherSuite() = %v, want %v", got, tt.want)
			}
		})
	}
}
