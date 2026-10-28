package atlasfga

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockServer is a tiny in-memory stand-in for the Atlas /v1/fga surface: just
// enough of the wire contract to exercise the client end to end.
func mockServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	tuples := map[string]bool{} // "user|relation|object"
	var auths []string          // captured Authorization headers
	key := func(u, r, o string) string { return u + "|" + r + "|" + o }

	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/v1/fga/stores/", func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		if strings.Contains(r.URL.Path, "/stores/missing/") {
			write(w, 404, map[string]interface{}{"errors": []map[string]string{{"code": "store_id_not_found", "message": "Unknown FGA store."}}})
			return
		}
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/check"):
			var p CheckParams
			_ = json.Unmarshal(body, &p)
			write(w, 200, CheckResult{Object: "fga.check", Allowed: tuples[key(p.User, p.Relation, p.Object)], AuthorizationModelID: "model_1"})
		case strings.HasSuffix(r.URL.Path, "/write"):
			var p WriteParams
			_ = json.Unmarshal(body, &p)
			for _, tk := range p.Writes {
				tuples[key(tk.User, tk.Relation, tk.Object)] = true
			}
			for _, tk := range p.Deletes {
				delete(tuples, key(tk.User, tk.Relation, tk.Object))
			}
			write(w, 200, WriteResult{Object: "fga.write_result", Writes: len(p.Writes), Deletes: len(p.Deletes)})
		case strings.HasSuffix(r.URL.Path, "/list-objects"):
			var p ListObjectsParams
			_ = json.Unmarshal(body, &p)
			var objs []string
			for k := range tuples {
				parts := strings.Split(k, "|")
				if parts[0] == p.User && parts[1] == p.Relation && strings.HasPrefix(parts[2], p.Type+":") {
					objs = append(objs, parts[2])
				}
			}
			write(w, 200, ListObjectsResult{Object: "fga.list_objects", Objects: objs, AuthorizationModelID: "model_1"})
		case strings.HasSuffix(r.URL.Path, "/read"):
			var p ReadParams
			_ = json.Unmarshal(body, &p)
			var data []Tuple
			for k := range tuples {
				parts := strings.Split(k, "|")
				if (p.User == "" || parts[0] == p.User) && (p.Relation == "" || parts[1] == p.Relation) && (p.Object == "" || parts[2] == p.Object) {
					data = append(data, Tuple{Object: "fga.tuple", User: parts[0], Relation: parts[1], Target: parts[2], CreatedAt: 1})
				}
			}
			write(w, 200, ListPage[Tuple]{Object: "list", Data: data, HasMore: false})
		default:
			write(w, 404, map[string]interface{}{"errors": []map[string]string{{"code": "not_found", "message": r.URL.Path}}})
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &auths
}

func TestCheckAuthAndBaseURL(t *testing.T) {
	srv, auths := mockServer(t)
	c := New("sk_test_abc", WithBaseURL(srv.URL), WithStore("store_1"))
	if _, err := c.Check(context.Background(), CheckParams{User: "user:a", Relation: "viewer", Object: "doc:1"}); err != nil {
		t.Fatal(err)
	}
	if len(*auths) == 0 || (*auths)[0] != "Bearer sk_test_abc" {
		t.Fatalf("expected Bearer auth, got %v", *auths)
	}
}

func TestWriteThenCheck(t *testing.T) {
	srv, _ := mockServer(t)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("store_1"))
	ctx := context.Background()

	before, err := c.Check(ctx, CheckParams{User: "user:alice", Relation: "viewer", Object: "doc:readme"})
	if err != nil {
		t.Fatal(err)
	}
	if before.Allowed {
		t.Fatal("expected allowed=false before write")
	}

	w, err := c.WriteTuples(ctx, TupleKey{User: "user:alice", Relation: "viewer", Object: "doc:readme"})
	if err != nil {
		t.Fatal(err)
	}
	if w.Writes != 1 {
		t.Fatalf("expected 1 write, got %d", w.Writes)
	}

	after, err := c.Check(ctx, CheckParams{User: "user:alice", Relation: "viewer", Object: "doc:readme"})
	if err != nil {
		t.Fatal(err)
	}
	if !after.Allowed {
		t.Fatal("expected allowed=true after write")
	}
}

func TestListObjectsRoundTrip(t *testing.T) {
	srv, _ := mockServer(t)
	c := New("sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()
	store := c.Store("store_1")
	if _, err := store.Write(ctx, WriteParams{Writes: []TupleKey{
		{User: "user:bob", Relation: "editor", Object: "doc:1"},
		{User: "user:bob", Relation: "editor", Object: "doc:2"},
		{User: "user:bob", Relation: "editor", Object: "folder:x"},
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := store.ListObjects(ctx, ListObjectsParams{User: "user:bob", Relation: "editor", Type: "doc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("expected 2 docs, got %v", res.Objects)
	}
}

func TestReadEnvelope(t *testing.T) {
	srv, _ := mockServer(t)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("store_1"))
	ctx := context.Background()
	if _, err := c.WriteTuples(ctx, TupleKey{User: "user:x", Relation: "owner", Object: "doc:9"}); err != nil {
		t.Fatal(err)
	}
	page, err := c.Read(ctx, ReadParams{Object: "doc:9"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Object != "list" || len(page.Data) != 1 || page.Data[0].Target != "doc:9" {
		t.Fatalf("unexpected read page: %+v", page)
	}
}

func TestDefaultModelFolded(t *testing.T) {
	// Verify the default model id is folded into the body.
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p CheckParams
		_ = json.Unmarshal(body, &p)
		gotModel = p.AuthorizationModelID
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckResult{Object: "fga.check", Allowed: true})
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("s"), WithModel("model_pinned"))
	if _, err := c.Check(context.Background(), CheckParams{User: "u:a", Relation: "v", Object: "d:1"}); err != nil {
		t.Fatal(err)
	}
	if gotModel != "model_pinned" {
		t.Fatalf("expected folded model_pinned, got %q", gotModel)
	}
}

func TestAPIError(t *testing.T) {
	srv, _ := mockServer(t)
	c := New("sk_test", WithBaseURL(srv.URL))
	_, err := c.CheckIn(context.Background(), "missing", CheckParams{User: "u:a", Relation: "v", Object: "d:1"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.Code() != "store_id_not_found" || apiErr.Status != 404 {
		t.Fatalf("unexpected error: %+v", apiErr)
	}
}

func TestMissingStore(t *testing.T) {
	c := New("sk_test", WithBaseURL("http://unused"))
	if _, err := c.Check(context.Background(), CheckParams{User: "u", Relation: "r", Object: "o"}); err == nil {
		t.Fatal("expected a no-store error")
	}
}

func TestConditionContextConsistencyRoundTrip(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/write") {
			_, _ = w.Write([]byte(`{"object":"fga.write_result","writes":1,"deletes":0,"consistency_token":"tok1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"fga.check","allowed":true,"consistency_token":"tok2"}`))
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("s"))
	ctx := context.Background()

	cond := &Condition{Name: "in_window", Context: map[string]interface{}{"start": "a"}}
	w, err := c.WriteTuples(ctx, TupleKey{User: "user:a", Relation: "viewer", Object: "doc:1", Condition: cond})
	if err != nil {
		t.Fatal(err)
	}
	wc := got["writes"].([]interface{})[0].(map[string]interface{})["condition"].(map[string]interface{})
	if wc["name"] != "in_window" || w.ConsistencyToken != "tok1" {
		t.Fatalf("unexpected write: %v / %+v", got, w)
	}
	// A tuple without a condition must not send the key at all.
	if b, _ := json.Marshal(TupleKey{User: "u", Relation: "r", Object: "o"}); strings.Contains(string(b), "condition") {
		t.Fatalf("condition leaked: %s", b)
	}

	res, err := c.Check(ctx, CheckParams{User: "user:a", Relation: "viewer", Object: "doc:1",
		Context: map[string]interface{}{"now": "t"}, Consistency: ConsistencyHigherConsistency, ConsistencyToken: w.ConsistencyToken})
	if err != nil {
		t.Fatal(err)
	}
	if got["consistency"] != "HIGHER_CONSISTENCY" || got["consistency_token"] != "tok1" || got["context"].(map[string]interface{})["now"] != "t" {
		t.Fatalf("unexpected check body: %v", got)
	}
	if res.ConsistencyToken != "tok2" {
		t.Fatalf("unexpected check result: %+v", res)
	}
}

func TestListAllUsersFollowsPages(t *testing.T) {
	var tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/list-users") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var p ListUsersParams
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		tokens = append(tokens, p.ContinuationToken)
		w.Header().Set("Content-Type", "application/json")
		if p.ContinuationToken == "" {
			_, _ = w.Write([]byte(`{"object":"fga.list_users","users":["user:a","user:*"],"excluded_users":["user:x"],"continuation_token":"next","consistency_token":"c"}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"fga.list_users","users":["user:b"],"excluded_users":["user:x"],"continuation_token":null,"consistency_token":"c2"}`))
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("s"))
	res, err := c.ListAllUsers(context.Background(), ListUsersParams{
		Object: "doc:1", Relation: "viewer", UserFilters: []UserFilter{{Type: "user"}}, PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Users, ",") != "user:a,user:*,user:b" || len(res.ExcludedUsers) != 1 || res.ContinuationToken != nil || res.ConsistencyToken != "c2" {
		t.Fatalf("unexpected merged result: %+v", res)
	}
	if len(tokens) != 2 || tokens[1] != "next" {
		t.Fatalf("expected a second call with the token, got %v", tokens)
	}
}

func TestEachChangeFollowsPages(t *testing.T) {
	var uris []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uris = append(uris, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continuation_token") == "" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"fga.tuple_change","operation":"write","user":"user:a","relation":"viewer","target":"doc:1","consistency_token":"t","created_at":5}],"has_more":true,"continuation_token":"c1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"fga.tuple_change","operation":"delete","user":"user:a","relation":"viewer","target":"doc:1","condition":{"name":"n"},"consistency_token":"t2","created_at":6}],"has_more":false,"continuation_token":"c2"}`))
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithStore("s"))
	var ops []string
	var lastCond *Condition
	cursor, err := c.EachChange(context.Background(), ReadChangesParams{Type: "doc", PageSize: 1, StartTime: "2026-01-01T00:00:00Z"}, func(ch TupleChange) error {
		ops = append(ops, ch.Operation)
		lastCond = ch.Condition
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ops, ",") != "write,delete" || cursor != "c2" || lastCond == nil || lastCond.Name != "n" {
		t.Fatalf("unexpected walk: ops=%v cursor=%q cond=%+v", ops, cursor, lastCond)
	}
	if uris[0] != "GET /v1/fga/stores/s/changes?page_size=1&start_time=2026-01-01T00%3A00%3A00Z&type=doc" ||
		!strings.Contains(uris[1], "continuation_token=c1") {
		t.Fatalf("unexpected requests: %v", uris)
	}
}
