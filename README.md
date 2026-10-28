# atlas-fga-go

The Atlas **FGA** (fine-grained, relationship-based authorization — Zanzibar /
OpenFGA) client for Go. Native, standard-library-only, preconfigured for Atlas.

```bash
go get github.com/Atlas-Authorization/atlas-fga-go
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"

	atlasfga "github.com/Atlas-Authorization/atlas-fga-go"
)

func main() {
	ctx := context.Background()
	c := atlasfga.New("sk_live_...", atlasfga.WithStore("store_123"))

	// write a relationship tuple
	_, _ = c.WriteTuples(ctx, atlasfga.TupleKey{
		User: "user:alice", Relation: "viewer", Object: "doc:readme",
	})

	// ask an access question
	res, _ := c.Check(ctx, atlasfga.CheckParams{
		User: "user:alice", Relation: "viewer", Object: "doc:readme",
	})
	fmt.Println(res.Allowed) // true

	// list the objects a user can reach
	lo, _ := c.ListObjects(ctx, atlasfga.ListObjectsParams{
		User: "user:alice", Relation: "viewer", Type: "doc",
	})
	fmt.Println(lo.Objects) // [doc:readme]
}
```

Configuration falls back to the environment when not passed explicitly:
`ATLAS_SECRET_KEY`, `ATLAS_FGA_STORE_ID`, `ATLAS_FGA_MODEL_ID`, and
`ATLAS_FGA_URL` (base URL, default `https://api.atlasauth.net`).

## Operations

| Method | Atlas route |
| --- | --- |
| `Check` / `CheckIn` | `POST /v1/fga/stores/:store/check` |
| `BatchCheck` / `BatchCheckIn` | `POST /v1/fga/stores/:store/batch-check` |
| `Write` / `WriteTuples` / `DeleteTuples` | `POST /v1/fga/stores/:store/write` |
| `Read` / `ReadIn` | `POST /v1/fga/stores/:store/read` |
| `ListObjects` / `ListObjectsIn` | `POST /v1/fga/stores/:store/list-objects` |
| `ListUsers` / `ListUsersIn` / `ListAllUsers` | `POST /v1/fga/stores/:store/list-users` |
| `ReadChanges` / `ReadChangesIn` / `EachChange` | `GET /v1/fga/stores/:store/changes` |
| `Expand` / `ExpandIn` | `POST /v1/fga/stores/:store/expand` |
| `ListStores` / `CreateStore` / `GetStore` / `DeleteStore` | `/v1/fga/stores` |
| `ListModels` / `CreateModel` / `GetModel` | `/v1/fga/stores/:store/authorization-models` |

`Client.Store("store_id")` returns a `*BoundStore` with the store id fixed, for
the common single-store case.

## Conditions and context

A tuple may carry a `Condition` (`Name` plus an optional `Context`); the model
declares conditions in the `Conditions` map of `AuthorizationModelInput`
(`ConditionDefinition` describes an entry: `Expression` and `Parameters`, e.g.
`{"type_name": "TYPE_NAME_STRING"}`):

```go
c.WriteTuples(ctx, atlasfga.TupleKey{
	User: "user:alice", Relation: "viewer", Object: "doc:readme",
	Condition: &atlasfga.Condition{Name: "in_window", Context: map[string]interface{}{"expires": "2027-01-01T00:00:00Z"}},
})
c.Check(ctx, atlasfga.CheckParams{
	User: "user:alice", Relation: "viewer", Object: "doc:readme",
	Context: map[string]interface{}{"request_time": "2026-10-27T00:00:00Z"},
})
```

`Context` (request-time values for condition parameters) is accepted by
`CheckParams`, `ListObjectsParams`, `ListUsersParams`, and on each
`BatchCheckItem`. Tuples returned by `Read` and the changes feed set
`Condition` only when they have one.

## Consistency

`CheckParams`, `BatchCheckParams`, `ListObjectsParams` and `ListUsersParams`
accept `Consistency` (`ConsistencyUnspecified`, `ConsistencyMinimizeLatency`,
`ConsistencyHigherConsistency`) and `ConsistencyToken`. `MINIMIZE_LATENCY` (the
default) may be served from a short-lived cache; `HIGHER_CONSISTENCY` bypasses
it. Write and read results carry a `ConsistencyToken`; pass the token from a
write to guarantee the read reflects at least that write, e.g. right after
revoking access:

```go
w, _ := c.DeleteTuples(ctx, atlasfga.TupleKey{User: "user:alice", Relation: "viewer", Object: "doc:readme"})
res, _ := c.Check(ctx, atlasfga.CheckParams{
	User: "user:alice", Relation: "viewer", Object: "doc:readme",
	ConsistencyToken: w.ConsistencyToken,
}) // res.Allowed == false
```

## Listing users and following changes

```go
res, _ := c.ListUsers(ctx, atlasfga.ListUsersParams{
	Object: "doc:readme", Relation: "viewer",
	UserFilters: []atlasfga.UserFilter{{Type: "user"}},
})
// res.Users: "user:alice", a userset "team:eng#member", or a wildcard "user:*"
// res.ExcludedUsers: ids a wildcard does not cover
all, _ := c.ListAllUsers(ctx, params) // follows ContinuationToken across pages

cursor, _ := c.EachChange(ctx, atlasfga.ReadChangesParams{Type: "doc"}, func(ch atlasfga.TupleChange) error {
	fmt.Println(ch.Operation, ch.User, ch.Relation, ch.Target)
	return nil
})
// Keep cursor (returned even on the last page) and pass it later as
// ReadChangesParams.ContinuationToken to receive only newer changes.
```

`UserFilters` takes exactly one filter; `PageSize` is 1-1000 for `ListUsers`
(default 1000) and 1-100 for `ReadChanges` (default 50); `StartTime` is RFC 3339.

## Errors

Non-2xx responses return `*APIError` carrying Atlas's `{ errors: [...] }`
envelope:

```go
_, err := c.Check(ctx, params)
var apiErr *atlasfga.APIError
if errors.As(err, &apiErr) && apiErr.Code() == "store_id_not_found" { /* ... */ }
```

## Relationship to OpenFGA

Atlas's engine is **OpenFGA-shaped** (same model DSL/JSON, same tuple
vocabulary, same operations) and also exposes an OpenFGA **wire-compatible**
mirror at `/v1/openfga` that the stock `github.com/openfga/go-sdk` can drive
for `check` / `write` / stores / models (set its `ApiUrl` to
`https://<host>/v1/openfga`, credentials = Atlas secret key as `ApiToken`).

This client targets the **native `/v1/fga` surface** because `list-objects`,
`read`, and `expand` live only there (not on `/v1/openfga`), and `/v1/fga` wraps
responses in Atlas's `{object, ...}` envelope — `Read` returns a
`ListPage[Tuple]` (`{object:"list", data, has_more}`) with each tuple's object
named `Target`, rather than OpenFGA's `{tuples, continuation_token}`. Auth is an
Atlas secret key (`Authorization: Bearer sk_…`, scopes `fga:read`/`fga:write`),
not an OpenFGA store-scoped token. Model format and tuple semantics are
identical to OpenFGA.
