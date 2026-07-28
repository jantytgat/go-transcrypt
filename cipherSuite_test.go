package transcrypt

import "testing"

func TestCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  string
	}{
		{AES_256_GCM, "AES_256_GCM"},
		{CHACHA20_POLY1305, "CHACHA20_POLY1305"},
		{CipherSuite(99), "CipherSuite(99)"},
	}
	for _, tt := range tests {
		if got := tt.suite.String(); got != tt.want {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", byte(tt.suite), got, tt.want)
		}
	}
	// String and GetCipherSuite must stay inverse for the known suites.
	for _, suite := range []CipherSuite{AES_256_GCM, CHACHA20_POLY1305} {
		got, err := GetCipherSuite(suite.String())
		if err != nil || got != suite {
			t.Errorf("GetCipherSuite(%q) = %v, %v; want %v", suite.String(), got, err, suite)
		}
	}
}

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
