package cryptutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateJWKFromBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cert    string
		want    string
		wantErr bool
	}{
		{
			"good RS256",
			"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
			`{"use":"sig","kty":"RSA","kid":"f0cc8033b422c2a199dcb456dde29589a9f5edd27d1c345bdf308957e957becf","alg":"RS256","n":"67KjqmQYGq0MVtACVpeCmXminlQbDPGLmsZAUEwueHQnrt3WtvpDOm6AlaJMUnW-Hu55jjokalKeVjTKmgYGbqUzVDoMbPDaHekltdBTMGlOUFsP4UJSDrO4zdN-zo428TX2PnG2FCdVKGy4PE8ilHbWLcr871YjV51fw8CLDX9PZJNu861CF7V9iEJm6sSfQlmnhN8j3-WzVbPQNy1WsR7i9e9j63EqKt22Q9OXL-WAcKskoISmCNVRUAjU8YRVcgQJB-zQ34AQPlz0Op5O_QN_MedjaF8wLS-iv_zviS8cqPbxo6sLq6FNTltk_QkxeCeKKTQe_3kPYvQAdnl65Q","e":"AQAB","d":"wE-MrL1o0XM6qyajkcWjgNg3MFpNi_0VvF5gIWRXUl7r9gj5ZWjDK8z3y5-WCH4bdx97POoBxmLM4GfIm22pF-RhAisu8kB-p4MRCs0E4244wOXcCh7T1z0a343eXGi7OYqe9YpQVxdUq1wx4rtq6pof3VNPl3S_93_noE_c5U_XOK0aPL758nF89a9rmhFb0y5V7paHIsRJK9ifUtpaMmk6JBDbHtN4iFmWczOCGKmdPGzcaB1_twLnlyx0PrBQydl2VFiiRRtLtmcBpe21YhNT-cGwBpoNgseQe0vrXdjyUVqpKHqnKrxFgbLRP0A6dYlPAfM2wMLXK3cPTL8woQ","p":"82jhXbXPSPPWAOiR4xLLCuD9rwUFHd29wtiZ7JTLaeDDG6euqXDpJv72CTyP-qr-y48fxTDeMewlrAUmyg0SPj6-hVHe76U2Usv2iaTWmFIYy5m2jGeeCYtScFPRvnelMUHJeT_E0GUiTKADpf05z7KeCS2PpOtWzU8NK-4hwrk","q":"9-OkTcZrOpBHOXM3igu98BsC8oGBg6FKDOWX4Up8expsXoae1a655pxAddld7TmyQqlbuVcLCMAxtCvsGB6Tv737d0in9OBt8FuzAr7NXHuCCHJz7D5YRrWGmtjrNrCq8BkdBKIs8a4-PJik-RDp1YOzd9esWBZ42DEkdJ8Zk40","dp":"rJjXDULpK_qy6cv__nsJ_LnTSLKPkUD12N8MLmTH5FjbIJYDVOTafqtVvPDzyzRLHf5r8cCYHeAsSlEQ0z73i6mkIRcPtPB6l7VHKQz4mePE70Ic3mxu9KeVGk9lL-DZAxd6DH76SScdbiYc0CvCPZOTWkCzVacG0uhWF6twxwk","dq":"jrQeAigX0r78QbZyYqYf0fm62KB1TrGrT4FczfVzc-riOAiHp7vOiVOqSC26RLbSSE3239ucHo2GD5K5d6kipV9ZRHIvPml04MnpY8szrensEbDRy06Ywxv9QWdfATzzKwVKD0DNXtRQP9IgJsH121TWHEesj4lgSBUCR6DPuIE","qi":"gXD4BAh4HTcxP8gGWTTgI8vYOMz7jyFN1C_zTTQcA59BuTQRg_UJooa0KbzrXMB_Syr_kMpgIjP38ZLdcUzgGaQU6BxJZMI7p98uArep8LfFfae9kf1d1wkvj5_BpwvGxsj7xpBw1O2ajN1HXcGx9Fv4eNP-Pu8aRtCAkcE4rbM"}`,
			false,
		},
		{
			"good SS256",
			"LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUJlMFRxbXJkSXBZWE03c3pSRERWYndXOS83RWJHVWhTdFFJalhsVHNXM1BvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFb0xaRDI2bEdYREhRQmhhZkdlbEVmRDdlNmYzaURjWVJPVjdUbFlIdHF1Y1BFL2hId2dmYQpNY3FBUEZsRmpueUpySXJhYTFlQ2xZRTJ6UktTQk5kNXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=",
			`{"use":"sig","kty":"EC","kid":"d591aa6e01e57ea8b80f349dc5de8517aa7b1f12f77700d89cbdba83938c0c61","crv":"P-256","alg":"ES256","x":"oLZD26lGXDHQBhafGelEfD7e6f3iDcYROV7TlYHtquc","y":"DxP4R8IH2jHKgDxZRY58iayK2mtXgpWBNs0SkgTXeaU","d":"F7ROqat0ilhczuzNEMNVvBb3_sRsZSFK1AiNeVOxbc8"}`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(tt.cert)
			if err != nil {
				t.Fatal(err)
			}

			out, err := PrivateJWKFromBytes(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateJWKFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(got), tt.want); diff != "" {
				t.Errorf("PrivateJWKFromBytes() want %v", diff)
			}
		})
	}
}

func TestPublicJWKFromBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cert    string
		want    string
		wantErr bool
	}{
		{
			"good RS256",
			"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
			`{"use":"sig","kty":"RSA","kid":"f0cc8033b422c2a199dcb456dde29589a9f5edd27d1c345bdf308957e957becf","alg":"RS256","n":"67KjqmQYGq0MVtACVpeCmXminlQbDPGLmsZAUEwueHQnrt3WtvpDOm6AlaJMUnW-Hu55jjokalKeVjTKmgYGbqUzVDoMbPDaHekltdBTMGlOUFsP4UJSDrO4zdN-zo428TX2PnG2FCdVKGy4PE8ilHbWLcr871YjV51fw8CLDX9PZJNu861CF7V9iEJm6sSfQlmnhN8j3-WzVbPQNy1WsR7i9e9j63EqKt22Q9OXL-WAcKskoISmCNVRUAjU8YRVcgQJB-zQ34AQPlz0Op5O_QN_MedjaF8wLS-iv_zviS8cqPbxo6sLq6FNTltk_QkxeCeKKTQe_3kPYvQAdnl65Q","e":"AQAB"}`,
			false,
		},

		{
			"good ES256",
			"LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUJlMFRxbXJkSXBZWE03c3pSRERWYndXOS83RWJHVWhTdFFJalhsVHNXM1BvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFb0xaRDI2bEdYREhRQmhhZkdlbEVmRDdlNmYzaURjWVJPVjdUbFlIdHF1Y1BFL2hId2dmYQpNY3FBUEZsRmpueUpySXJhYTFlQ2xZRTJ6UktTQk5kNXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=",
			`{"use":"sig","kty":"EC","kid":"d591aa6e01e57ea8b80f349dc5de8517aa7b1f12f77700d89cbdba83938c0c61","crv":"P-256","alg":"ES256","x":"oLZD26lGXDHQBhafGelEfD7e6f3iDcYROV7TlYHtquc","y":"DxP4R8IH2jHKgDxZRY58iayK2mtXgpWBNs0SkgTXeaU"}`,
			false,
		},
		{
			"bad key decode",
			"LS0t",
			`null`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(tt.cert)
			if err != nil {
				t.Fatal(err)
			}

			out, err := PublicJWKFromBytes(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicJWKFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(got), tt.want); diff != "" {
				t.Errorf("PublicJWKFromBytes() want %v", diff)
			}
		})
	}
}

func TestSignatureAlgorithmForKey(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		alg, err := SignatureAlgorithmForKey(key)
		assert.NoError(t, err)
		assert.Equal(t, jose.ES256, alg)
		alg, err = SignatureAlgorithmForKey(key.Public())
		assert.NoError(t, err)
		assert.Equal(t, jose.ES256, alg)
	})
	t.Run("rsa", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		alg, err := SignatureAlgorithmForKey(key)
		assert.NoError(t, err)
		assert.Equal(t, jose.RS256, alg)
		alg, err = SignatureAlgorithmForKey(key.Public())
		assert.NoError(t, err)
		assert.Equal(t, jose.RS256, alg)
	})
	t.Run("ed25519", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = SignatureAlgorithmForKey(priv)
		assert.Error(t, err)
		_, err = SignatureAlgorithmForKey(pub)
		assert.Error(t, err)
	})
}
