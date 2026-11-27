package netconf

import "testing"

func TestNormalizeWifiAttempts(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int
	}{
		{-3, DefaultWifiAttempts},
		{0, DefaultWifiAttempts},
		{1, 1},
		{4, 4},
		{99, MaxWifiAttempts},
	} {
		if got := NormalizeWifiAttempts(tc.in); got != tc.want {
			t.Errorf("NormalizeWifiAttempts(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
