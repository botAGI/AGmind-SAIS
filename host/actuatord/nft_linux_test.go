//go:build linux

package actuatord

import (
	"testing"
	"time"

	"github.com/google/nftables/expr"
)

func TestCanonicalNftTransactionShapeIsFixed(t *testing.T) {
	spec := NftApplySpec{
		PlanID:           "plan_0123456789abcdef0123456789abcdef",
		DestinationIPv4:  "1.1.1.1",
		TTL:              120 * time.Second,
		TargetNetNSInode: 789,
	}
	table, chain, set, element, rule, err := canonicalNftObjects(spec)
	if err != nil {
		t.Fatal(err)
	}
	if table.Name != nftTableName || !exactNftChain(chain) || !exactNftSet(set) {
		t.Fatalf("table=%+v chain=%+v set=%+v", table, chain, set)
	}
	if _, ok := exactNftRule(rule, table, chain); !ok ||
		string(element.Key) != string([]byte{1, 1, 1, 1}) ||
		element.Timeout != 120*time.Second || element.Comment != nftOwnerMarker {
		t.Fatalf("element=%+v rule=%+v", element, rule)
	}
	firstHash, err := expectedNftRulesetSHA256(spec)
	if err != nil || !digestPattern.MatchString(firstHash) {
		t.Fatalf("hash=%q err=%v", firstHash, err)
	}
	payload := rule.Exprs[0].(*expr.Payload)
	payload.Offset = 15
	if _, ok := exactNftRule(rule, table, chain); ok {
		t.Fatal("non-destination payload shape was accepted")
	}
}
