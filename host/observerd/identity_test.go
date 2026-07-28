//go:build linux

package observerd

import (
	"fmt"
	"strings"
	"testing"
)

func TestPrivateLinuxIdentityParsesEffectiveCAPNETADMIN(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "present",
			raw:  "Name:\texample\nCapEff:\t0000000000001000\n",
			want: true,
		},
		{
			name: "absent",
			raw:  "Name:\texample\nCapEff:\t0000000000000000\n",
			want: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseEffectiveCapNetAdmin([]byte(testCase.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("got=%v want=%v", got, testCase.want)
			}
		})
	}

	for name, raw := range map[string]string{
		"missing":   "Name:\texample\n",
		"duplicate": "CapEff:\t0000000000001000\nCapEff:\t0\n",
		"malformed": "CapEff:\tnot-hex\n",
		"oversized": "CapEff:\t10000000000000000\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseEffectiveCapNetAdmin([]byte(raw)); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}

func procStatFixture(pid int, command string, startTicks string) []byte {
	fields := []string{"S"}
	for field := 4; field <= 21; field++ {
		fields = append(fields, fmt.Sprintf("%d", field))
	}
	fields = append(fields, startTicks)
	return []byte(fmt.Sprintf(
		"%d (%s) %s\n",
		pid,
		command,
		strings.Join(fields, " "),
	))
}

func TestPrivateLinuxIdentityParsesStartTicksAroundHostileCommand(
	t *testing.T,
) {
	raw := procStatFixture(4242, "hostile ) command ( text", "987654321")
	got, err := parseProcStartTicks(raw, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if got != 987654321 {
		t.Fatalf("start ticks=%d", got)
	}
	for name, candidate := range map[string][]byte{
		"pid mismatch": procStatFixture(4243, "command", "987654321"),
		"zero":         procStatFixture(4242, "command", "0"),
		"noninteger":   procStatFixture(4242, "command", "1.5"),
		"truncated":    []byte("4242 (command) S 1 2\n"),
		"trailing": append(
			procStatFixture(4242, "command", "987654321"),
			[]byte("unexpected")...,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProcStartTicks(candidate, 4242); err == nil {
				t.Fatalf("accepted %q", candidate)
			}
		})
	}
}

func TestPrivateLinuxIdentityRequiresExactDockerCgroupV2Shape(
	t *testing.T,
) {
	for _, path := range []string{
		"/system.slice/docker-" + inventoryTestIDOne + ".scope",
		"/docker/" + inventoryTestIDOne,
	} {
		raw := []byte("0::" + path + "\n")
		got, err := parseDockerCgroupV2(raw, inventoryTestIDOne)
		if err != nil {
			t.Fatalf("path=%s err=%v", path, err)
		}
		if got != path {
			t.Fatalf("got=%q want=%q", got, path)
		}
	}
	for name, raw := range map[string]string{
		"prefix only": "0::/system.slice/docker-" +
			inventoryTestIDOne[:12] + ".scope\n",
		"wrong id": "0::/system.slice/docker-" +
			inventoryTestIDTwo + ".scope\n",
		"v1": "2:cpu:/docker/" + inventoryTestIDOne + "\n",
		"generic substring": "0::/user.slice/" +
			inventoryTestIDOne + "\n",
		"duplicate": "0::/docker/" + inventoryTestIDOne +
			"\n0::/docker/" + inventoryTestIDOne + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDockerCgroupV2(
				[]byte(raw),
				inventoryTestIDOne,
			); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}
