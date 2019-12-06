package main

import (
	"fmt"
	"testing"
)

const (
	privKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDjYaMMqh6qDYMNrqaOhTsRlXxYN+g/dlPjiN3CmASfus9hiCJg
4hH81tNhLHck3/ujcdMZS8exzn0eO1EAyqRq55X2EdJPTFGHAABf7D5xDpNK5yCg
771Vf4y4l3erbpfyntZrOI5JveY0XD9NEc4onQ9/NP2TYFB0pDxmrV4lwQIEAQuu
7QKBgC/IBMj0rUmyU1NYuZDrbNZTBLGhhan4PHiC4Kj5FzSOw5Qe3l4RaHptvpx8
3WCXCfsiEwQ3FQ/cJObM/5Gdj5thebIOWaoDmSpFSUu4OJg5Ro8IAOjG0znFpPbK
w4K1eAIg1zmouSVLIRS9V8SPJ0oFVn0mLpbj4LKEUKvXHj/VAkEA+S5wwZArmjYf
3pw1cx4BBDjxLyFHZqRtBDo/nW7LXF/NajKb3VLGfyxyW2oZsMBG02pNQKpDd6km
z11w3f2ypQJBAOmae8ixvRZTC0ywEAdbOYrsxgux/f4c8yBujaNSfXU5b8kSUoHm
xlj5QLKzw9MeiiMKRrT8shEgJbfT7UrkR+0CQQCI92lTcUQrQUBHUFcyIwYQKNEk
heqpb7Wo2Et6KbvJPecAndryrUOeRNe+3WMuc4I1FeiQ5sDsFG6X7RQQOvvpAkEA
zMK1WJxY/tpvi/m/md+mVuwxqUyyqjX04AMixFVD8syWR/mKmisBtlAeydsA6V8F
+hzIntMqHC4P3z4IeXKveQJBAPcZhAASRulxSuez4F+6TYVAGCvp/A9zqa5UFj9x
rzu3974W1wsvmXAEOgi9WXzKZDRMqSKnW+VBmRt5JeI99LY=
-----END RSA PRIVATE KEY-----`
	addr = "testvh5q4jmneo5j.onion"
)

func TestComputeKey(t *testing.T) {
	cadd, err := ComputeAddr(privKey)
	if err != nil {
		t.Error("error computing key")
	}
	if cadd != addr {
		t.Error(fmt.Sprintf("expected %s got %s", addr, cadd))
	}
}
