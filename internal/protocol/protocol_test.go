package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	in := &Request{
		Version:     Version,
		Host:        "vps",
		User:        "agent",
		UID:         1000,
		Prompt:      "[sudo] password for agent: ",
		ParentName:  "sudo",
		ParentEUID:  0,
		ParentArgs:  []string{"sudo", "-A", "true"},
		InvokerArgs: []string{"bash", "-c", "sudo -A true"},
		Cwd:         "/home/agent",
	}
	var buf bytes.Buffer
	if err := WriteRequest(&buf, in); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) || bytes.Count(buf.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("request is not a single line: %q", buf.String())
	}
	out, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Host != in.Host || out.Prompt != in.Prompt || len(out.ParentArgs) != 3 || out.ParentEUID != 0 {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestReadRequestRejects(t *testing.T) {
	for name, input := range map[string]string{
		"wrong version": `{"v":2}` + "\n",
		"no newline":    `{"v":1}`,
		"not json":      "hello\n",
		"oversized":     `{"v":1,"prompt":"` + strings.Repeat("a", MaxRequestSize) + `"}` + "\n",
	} {
		if _, err := ReadRequest(strings.NewReader(input)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		status  Status
		payload string
	}{
		{StatusOK, "s3cret pass|with\x00odd bytes"},
		{StatusOK, ""},
		{StatusDenied, "denied"},
		{StatusTimeout, "no answer"},
	} {
		var buf bytes.Buffer
		if err := WriteResponse(&buf, tc.status, []byte(tc.payload)); err != nil {
			t.Fatal(err)
		}
		st, p, err := ReadResponse(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if st != tc.status || string(p) != tc.payload {
			t.Errorf("got %v %q, want %v %q", st, p, tc.status, tc.payload)
		}
		if buf.Len() != 0 {
			t.Errorf("%d trailing bytes", buf.Len())
		}
	}
}

func TestResponseLimits(t *testing.T) {
	if err := WriteResponse(&bytes.Buffer{}, StatusOK, make([]byte, MaxPayload+1)); err == nil {
		t.Error("oversized payload written")
	}
	if _, _, err := ReadResponse(bytes.NewReader([]byte{1, 0xff, 0xff})); err == nil {
		t.Error("oversized length accepted")
	}
	if _, _, err := ReadResponse(bytes.NewReader([]byte{1, 0, 5, 'a', 'b'})); err == nil {
		t.Error("truncated payload accepted")
	}
}
