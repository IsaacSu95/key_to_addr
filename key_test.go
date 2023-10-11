package key_to_addr

import (
	"encoding/base64"
	"github.com/wumansgy/goEncrypt/aes"
	"testing"
)

func TestKey(t *testing.T) {
	pubkey := "034939abacf3371f0a9175f60e64b4af3655d96a334f3a06aa1b5e982e6172d575"
	k, err := NewKey(pubkey)
	if err != nil {
		panic(err)
	}
	t.Log("ETH :", k.ETHAddress())
	t.Log("BTC :", k.BTCAddress())
	t.Log("TRON:", k.TronAddress())
	t.Log("BCH :", k.BCHAddress())
	t.Log("DASH:", k.DashAddress())
	t.Log("DOGE:", k.DogeAddress())
}

func TestBase64(t *testing.T) {
	key := []byte("ADEVAIXUDIXKEFNB")
	data, err := aes.AesCbcEncrypt([]byte("testBase64"), key, nil)
	if err != nil {
		panic(err)
	}

	t.Log(base64.StdEncoding.EncodeToString(data))

}
