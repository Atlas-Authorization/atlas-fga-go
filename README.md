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
| `Expand` / `ExpandIn` | `POST /v1/fga/stores/:store/expand` |
| `ListStores` / `CreateStore` / `GetStore` / `DeleteStore` | `/v1/fga/stores` |
| `ListModels` / `CreateModel` / `GetModel` | `/v1/fga/stores/:store/authorization-models` |

`Client.Store("store_id")` returns a `*BoundStore` with the store id fixed, for
the common single-store case.

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
