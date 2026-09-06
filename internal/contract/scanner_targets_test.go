package contract

import "testing"

func TestResolveTargetAcceptsCopiesWithoutUsingDisplayedFields(t *testing.T) {
	originals := []Target{
		BindTarget(Target{Domain: "one.example", Host: "192.0.2.1", Ports: []int{443}, Rate: 10}, 0),
		BindTarget(Target{Domain: "two.example", Host: "192.0.2.2", Port: 8443}, 1),
	}
	for index, original := range originals {
		copied := original
		copied.Domain, copied.Host, copied.URL = "changed.example", "198.51.100.1", "https://changed.example"
		copied.Port, copied.Rate, copied.Ports = 80, 100, []int{22}
		resolved, ok := ResolveTarget(copied, originals)
		if !ok || resolved != index {
			t.Fatalf("copy resolved to (%d, %t), want (%d, true)", resolved, ok, index)
		}
	}
}

func TestResolveTargetRejectsUnassignedForeignAndStaleTargets(t *testing.T) {
	native := Target{Domain: "example.com"}
	original := BindTarget(native, 0)
	originals := []Target{original}
	for name, target := range map[string]Target{
		"zero":           {},
		"fabricated":     native,
		"foreign":        BindTarget(native, 0),
		"negative index": BindTarget(native, -1),
		"past end":       BindTarget(native, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if index, ok := ResolveTarget(target, originals); ok {
				t.Fatalf("invalid target resolved to %d", index)
			}
		})
	}
	if _, ok := ResolveTarget(original, nil); ok {
		t.Fatal("target resolved against an empty registry")
	}
	if _, ok := ResolveTarget(original, []Target{native}); ok {
		t.Fatal("target resolved against an unbound original")
	}
	if _, ok := ResolveTarget(original, []Target{BindTarget(native, 0)}); ok {
		t.Fatal("stale target resolved against a replacement assignment")
	}
}

func TestBindTargetAlwaysCreatesAnIndependentReference(t *testing.T) {
	original := BindTarget(Target{}, 0)
	rebound := BindTarget(original, 0)
	if _, ok := ResolveTarget(rebound, []Target{original}); ok {
		t.Fatal("binding a target reused its old assignment reference")
	}
	if index, ok := ResolveTarget(rebound, []Target{rebound}); !ok || index != 0 {
		t.Fatalf("new assignment resolved to (%d, %t), want (0, true)", index, ok)
	}
}
