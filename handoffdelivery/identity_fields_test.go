package handoffdelivery

import (
	"flag"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
)

// leafPaths lists every leaf field reachable from t: struct fields by name, "[]" for a slice or array element, "{}" for a map value,
// following pointers. A struct with no exported fields (an opaque value type) is a leaf.
func leafPaths(t reflect.Type, path string, seen map[reflect.Type]int, out *[]string) {
	switch t.Kind() {
	case reflect.Ptr:
		leafPaths(t.Elem(), path, seen, out)
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			*out = append(*out, path)
			return
		}
		leafPaths(t.Elem(), path+"[]", seen, out)
	case reflect.Map:
		leafPaths(t.Elem(), path+"{}", seen, out)
		*out = append(*out, path+"{}#keys")
	case reflect.Struct:
		var exported []reflect.StructField
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.IsExported() {
				exported = append(exported, f)
			}
		}
		if len(exported) == 0 {
			*out = append(*out, path)
			return
		}
		if seen[t] > 2 {
			return
		}
		seen[t]++
		for _, f := range exported {
			leafPaths(f.Type, path+"."+f.Name, seen, out)
		}
		seen[t]--
	default:
		*out = append(*out, path)
	}
}

func bundleLeaves() []string {
	var out []string
	leafPaths(reflect.TypeOf(Bundle{}), "Bundle", map[reflect.Type]int{}, &out)
	sort.Strings(out)
	return out
}

var updateFields = flag.Bool("update-bundle-fields", false, "rewrite testdata/bundle_identity_fields.txt")

// excludedLeaf is the one place that says which parts of a bundle are NOT part of its semantic identity: the signature sets (each root
// holds the quorum it collected) of the certificates it forms locally. Every other leaf is hashed. The block's own QC (Block.Qc) is part
// of the proposed block and identical on every root, so it is hashed.
func excludedLeaf(path string) bool {
	for _, p := range []string{
		"Bundle.Proof.CommitQC.Signatures{}",
		"Bundle.Proof.OptionalQC.Signatures{}",
		"Bundle.Snapshot.Qc.Signatures{}",
		"Bundle.Snapshot.CommitQc.Signatures{}",
		"Bundle.Snapshot.ShardInfo[].UC.UnicitySeal.Signatures{}",
	} {
		if path == p || path == p+"#keys" {
			return true
		}
	}
	return false
}

// populate allocates every nil pointer, one element of every slice and one entry of every map reachable from v, with a deterministic
// value for every leaf, so that every leaf has something to perturb.
func populate(v reflect.Value, n *byte, depth map[reflect.Type]int) {
	populateField(v, "", n, depth)
}

// populateField fills what is still empty (a fixture value is kept) and gives every Version field the value 1, which the codecs accept.
func populateField(v reflect.Value, name string, n *byte, depth map[reflect.Type]int) {
	if !v.IsZero() && v.Kind() != reflect.Ptr && v.Kind() != reflect.Struct && v.Kind() != reflect.Slice && v.Kind() != reflect.Map {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		populateField(v.Elem(), name, n, depth)
	case reflect.Struct:
		if depth[v.Type()] > 2 {
			return
		}
		depth[v.Type()]++
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				populateField(v.Field(i), v.Type().Field(i).Name, n, depth)
			}
		}
		depth[v.Type()]--
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Len() == 0 {
				*n++
				v.SetBytes([]byte{*n, *n, *n})
			}
			return
		}
		if v.Len() == 0 {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		for i := 0; i < v.Len(); i++ {
			populateField(v.Index(i), name, n, depth)
		}
	case reflect.Map:
		if v.Len() > 0 {
			return
		}
		m := reflect.MakeMap(v.Type())
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		populateField(k, "", n, depth)
		populateField(e, "", n, depth)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.String:
		*n++
		v.SetString(string([]byte{'a' + *n%20}))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		*n++
		v.SetUint(uint64(*n))
		if name == "Version" {
			v.SetUint(1)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		*n++
		v.SetInt(int64(*n))
	case reflect.Bool:
		v.SetBool(true)
	}
}

// leafValues visits every leaf of an instance with its path (the same naming as leafPaths) and a function that perturbs it in place and
// returns the undo.
func leafValues(v reflect.Value, path string, fn func(path string, perturb func() func())) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			leafValues(v.Elem(), path, fn)
		}
	case reflect.Struct:
		var exported []int
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				exported = append(exported, i)
			}
		}
		if len(exported) == 0 {
			return
		}
		for _, i := range exported {
			leafValues(v.Field(i), path+"."+v.Type().Field(i).Name, fn)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			fn(path, func() func() {
				old := append([]byte(nil), v.Bytes()...)
				v.SetBytes(append(append([]byte(nil), old...), 0x7f))
				return func() { v.SetBytes(old) }
			})
			return
		}
		for i := 0; i < v.Len(); i++ {
			leafValues(v.Index(i), path+"[]", fn)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			leafValues(v.MapIndex(k), path+"{}", func(string, func() func()) {}) // map values are not addressable: perturbed through the map below
		}
		fn(path+"{}", func() func() {
			old := reflect.MakeMap(v.Type())
			for _, k := range v.MapKeys() {
				old.SetMapIndex(k, v.MapIndex(k))
			}
			nk, ne := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
			if nk.Kind() == reflect.String {
				nk.SetString("added-by-the-field-coverage-test")
			}
			v.SetMapIndex(nk, ne)
			return func() { v.Set(old) }
		})
		fn(path+"{}#keys", func() func() { return func() {} })
	case reflect.String:
		fn(path, func() func() { old := v.String(); v.SetString(old + "x"); return func() { v.SetString(old) } })
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fn(path, func() func() { old := v.Uint(); v.SetUint(old + 1); return func() { v.SetUint(old) } })
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fn(path, func() func() { old := v.Int(); v.SetInt(old + 1); return func() { v.SetInt(old) } })
	case reflect.Bool:
		fn(path, func() func() { old := v.Bool(); v.SetBool(!old); return func() { v.SetBool(old) } })
	}
}

// Every field of a bundle is either part of its semantic identity or listed as excluded, in a golden file: a field added to (or removed
// from) the bundle, or to anything it embeds, fails here until someone has decided which, and the decision is checked against what
// SemanticIdentity actually does by perturbing each leaf of a fully populated bundle.
func TestEveryBundleFieldIsExplicitlyHashedOrExcluded(t *testing.T) {
	var lines []string
	for _, p := range bundleLeaves() {
		class := "hashed"
		if excludedLeaf(p) {
			class = "excluded"
		}
		lines = append(lines, p+" "+class)
	}
	actual := strings.Join(lines, "\n") + "\n"
	const golden = "testdata/bundle_identity_fields.txt"
	if *updateFields {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(golden, []byte(actual), 0o644))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "run with -update-bundle-fields to create it")
	require.Equal(t, string(want), actual,
		"the bundle's fields changed: decide for each new field whether it belongs in SemanticIdentity (the default) or is a per-root signature set, update identity.go and excludedLeaf, then -update-bundle-fields")
}

func TestPerturbingEachBundleLeafChangesTheIdentityExactlyWhenItIsHashed(t *testing.T) {
	f := handoffbundle.New(t)
	b := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	var n byte
	populate(reflect.ValueOf(&b).Elem(), &n, map[reflect.Type]int{})
	want, err := semanticIdentityOf(b)
	require.NoError(t, err)
	checked := 0
	leafValues(reflect.ValueOf(&b).Elem(), "Bundle", func(path string, perturb func() func()) {
		undo := perturb()
		got, err := semanticIdentityOf(b)
		undo()
		if excludedLeaf(path) {
			require.NoError(t, err, path)
			require.Equal(t, want, got, "%s is excluded from the identity but changes it", path)
		} else if !strings.HasSuffix(path, "#keys") && err == nil {
			// (an encoding error means the codec itself commits to the value: a version or length it refuses)
			require.NotEqual(t, want, got, "%s is not part of the identity: it is neither hashed nor listed as excluded", path)
		}
		checked++
	})
	require.Greater(t, checked, 100)
}

// semanticIdentityOf hashes a bundle that is not a canonical persisted shape (populated with arbitrary values), without the
// encode/decode round trip SemanticIdentity uses to copy it.
func semanticIdentityOf(b Bundle) ([32]byte, error) {
	c := reflect.New(reflect.TypeOf(b)).Elem()
	deepCopy(c, reflect.ValueOf(b))
	cb := c.Interface().(Bundle)
	return identityOf(&cb)
}

func deepCopy(dst, src reflect.Value) {
	switch src.Kind() {
	case reflect.Ptr:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.New(src.Type().Elem()))
		deepCopy(dst.Elem(), src.Elem())
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			if src.Type().Field(i).IsExported() {
				deepCopy(dst.Field(i), src.Field(i))
			}
		}
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.MakeSlice(src.Type(), src.Len(), src.Len()))
		if src.Type().Elem().Kind() == reflect.Uint8 {
			reflect.Copy(dst, src)
			return
		}
		for i := 0; i < src.Len(); i++ {
			deepCopy(dst.Index(i), src.Index(i))
		}
	case reflect.Map:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.MakeMap(src.Type()))
		for _, k := range src.MapKeys() {
			e := reflect.New(src.Type().Elem()).Elem()
			deepCopy(e, src.MapIndex(k))
			dst.SetMapIndex(k, e)
		}
	default:
		dst.Set(src)
	}
}
