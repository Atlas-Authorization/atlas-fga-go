// Package atlasfga is the Atlas FGA client for Go — fine-grained,
// relationship-based authorization (Zanzibar / OpenFGA) served by Atlas's
// in-house engine at the Backend API's /v1/fga surface.
//
// It is a NATIVE client, not a wrapper over github.com/openfga/go-sdk: Atlas's
// FGA API is OpenFGA-SHAPED but not byte-for-byte wire-identical (it wraps
// responses in an {object, ...} envelope, returns read as a list page, and
// mounts list-objects/read/expand only on /v1/fga — the OpenFGA wire-compatible
// mirror at /v1/openfga covers only check/write/stores/models). See the README
// "Relationship to OpenFGA" section.
//
// Depends on nothing but the standard library. Every request is authenticated
// with an Atlas secret key: Authorization: Bearer sk_...
//
//	c := atlasfga.New("sk_live_...", atlasfga.WithStore("store_123"))
//	res, err := c.Check(ctx, atlasfga.CheckParams{User: "user:alice", Relation: "viewer", Object: "doc:readme"})
//	if err == nil && res.Allowed { /* ... */ }
package atlasfga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// DefaultBaseURL is the Atlas Backend API origin, overridable with WithBaseURL.
const DefaultBaseURL = "https://api.atlasauth.net"

const userAgent = "atlasauth-fga-go"

// Client is the Atlas FGA client. Safe for concurrent use.
type Client struct {
	baseURL    string
	secretKey  string
	storeID    string
	modelID    string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the Backend API origin (default DefaultBaseURL, or the
// ATLAS_FGA_URL env var).
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") } }

// WithStore sets the default store id applied to every store-scoped call.
func WithStore(id string) Option { return func(c *Client) { c.storeID = id } }

// WithModel sets the default authorization model id folded into query bodies.
func WithModel(id string) Option { return func(c *Client) { c.modelID = id } }

// WithHTTPClient injects a custom *http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// New constructs a Client. The secret key falls back to ATLAS_SECRET_KEY, the
// base URL to ATLAS_FGA_URL, the store to ATLAS_FGA_STORE_ID and the model to
// ATLAS_FGA_MODEL_ID when not set explicitly.
func New(secretKey string, opts ...Option) *Client {
	if secretKey == "" {
		secretKey = os.Getenv("ATLAS_SECRET_KEY")
	}
	c := &Client{
		baseURL:    firstNonEmpty(os.Getenv("ATLAS_FGA_URL"), DefaultBaseURL),
		secretKey:  secretKey,
		storeID:    os.Getenv("ATLAS_FGA_STORE_ID"),
		modelID:    os.Getenv("ATLAS_FGA_MODEL_ID"),
		httpClient: http.DefaultClient,
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	for _, o := range opts {
		o(c)
	}
	return c
}

/* ---- wire types -------------------------------------------------------- */

// Condition attaches a named model condition to a tuple; Context holds the
// values bound to the condition's parameters at write time (optional).
type Condition struct {
	Name    string                 `json:"name"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// ConditionDefinition is one entry of an authorization model's top-level
// conditions map (for AuthorizationModelInput.Conditions). Parameters maps a
// parameter name to its type, e.g. {"type_name": "TYPE_NAME_STRING"}.
type ConditionDefinition struct {
	Name       string                            `json:"name,omitempty"`
	Expression string                            `json:"expression"`
	Parameters map[string]map[string]interface{} `json:"parameters,omitempty"`
}

// Read-consistency modes for the Consistency request field. MinimizeLatency
// (the default) may be served from a short-lived cache; HigherConsistency
// bypasses it.
const (
	ConsistencyUnspecified       = "UNSPECIFIED"
	ConsistencyMinimizeLatency   = "MINIMIZE_LATENCY"
	ConsistencyHigherConsistency = "HIGHER_CONSISTENCY"
)

// TupleKey is a relationship tuple. Object is the target as "type:id".
// Condition is optional.
type TupleKey struct {
	User      string     `json:"user"`
	Relation  string     `json:"relation"`
	Object    string     `json:"object"`
	Condition *Condition `json:"condition,omitempty"`
}

// Tuple is a stored relationship tuple as returned by Read.
type Tuple struct {
	Object    string `json:"object"`
	User      string `json:"user"`
	Relation  string `json:"relation"`
	Target    string `json:"target"`
	CreatedAt int64  `json:"created_at"`
	// Condition is set only when the tuple has one.
	Condition *Condition `json:"condition,omitempty"`
}

// Store is an FGA store.
type Store struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// AuthorizationModel is a versioned OpenFGA authorization model.
type AuthorizationModel struct {
	Object        string                 `json:"object"`
	ID            string                 `json:"id"`
	StoreID       string                 `json:"store_id"`
	SchemaVersion string                 `json:"schema_version"`
	Model         map[string]interface{} `json:"model,omitempty"`
	CreatedAt     int64                  `json:"created_at"`
}

// AuthorizationModelInput is an OpenFGA authorization model to persist.
type AuthorizationModelInput struct {
	TypeDefinitions []interface{}          `json:"type_definitions"`
	SchemaVersion   string                 `json:"schema_version,omitempty"`
	Conditions      map[string]interface{} `json:"conditions,omitempty"`
}

// ListPage is the Atlas list envelope.
type ListPage[T any] struct {
	Object  string `json:"object"`
	Data    []T    `json:"data"`
	HasMore bool   `json:"has_more"`
}

// CheckParams resolves a single access question.
type CheckParams struct {
	User                 string     `json:"user"`
	Relation             string     `json:"relation"`
	Object               string     `json:"object"`
	AuthorizationModelID string     `json:"authorization_model_id,omitempty"`
	ContextualTuples     []TupleKey `json:"contextual_tuples,omitempty"`
	// Context supplies request-time values for condition parameters.
	Context map[string]interface{} `json:"context,omitempty"`
	// Consistency is one of the Consistency* constants; ConsistencyToken (from
	// a prior write) guarantees the read reflects at least that write.
	Consistency      string `json:"consistency,omitempty"`
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// CheckResult is a single check verdict.
type CheckResult struct {
	Object               string `json:"object"`
	Allowed              bool   `json:"allowed"`
	AuthorizationModelID string `json:"authorization_model_id"`
	ConsistencyToken     string `json:"consistency_token,omitempty"`
}

// WriteParams writes and/or deletes tuples in one atomic call.
type WriteParams struct {
	Writes  []TupleKey `json:"writes,omitempty"`
	Deletes []TupleKey `json:"deletes,omitempty"`
}

// WriteResult acknowledges a write.
type WriteResult struct {
	Object  string `json:"object"`
	Writes  int    `json:"writes"`
	Deletes int    `json:"deletes"`
	// ConsistencyToken: pass it as ConsistencyToken on a later read to see this write.
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// ReadParams queries stored tuples by any of user / relation / object.
type ReadParams struct {
	User     string `json:"user,omitempty"`
	Relation string `json:"relation,omitempty"`
	Object   string `json:"object,omitempty"`
}

// ListObjectsParams lists the objects of a type a user has a relation to.
type ListObjectsParams struct {
	User                 string                 `json:"user"`
	Relation             string                 `json:"relation"`
	Type                 string                 `json:"type"`
	AuthorizationModelID string                 `json:"authorization_model_id,omitempty"`
	ContextualTuples     []TupleKey             `json:"contextual_tuples,omitempty"`
	Context              map[string]interface{} `json:"context,omitempty"`
	Consistency          string                 `json:"consistency,omitempty"`
	ConsistencyToken     string                 `json:"consistency_token,omitempty"`
}

// ListObjectsResult is the list-objects verdict (objects as "type:id").
type ListObjectsResult struct {
	Object               string   `json:"object"`
	Objects              []string `json:"objects"`
	AuthorizationModelID string   `json:"authorization_model_id"`
	ConsistencyToken     string   `json:"consistency_token,omitempty"`
}

// UserFilter selects the kind of users to list: a Type, optionally narrowed to
// usersets of Relation (returned as "type:id#relation").
type UserFilter struct {
	Type     string `json:"type"`
	Relation string `json:"relation,omitempty"`
}

// ListUsersParams lists the users with a relation to an object. UserFilters
// must hold exactly one filter. PageSize is 1-1000 (default 1000).
type ListUsersParams struct {
	Object               string                 `json:"object"`
	Relation             string                 `json:"relation"`
	UserFilters          []UserFilter           `json:"user_filters"`
	AuthorizationModelID string                 `json:"authorization_model_id,omitempty"`
	ContextualTuples     []TupleKey             `json:"contextual_tuples,omitempty"`
	Context              map[string]interface{} `json:"context,omitempty"`
	Consistency          string                 `json:"consistency,omitempty"`
	ConsistencyToken     string                 `json:"consistency_token,omitempty"`
	PageSize             int                    `json:"page_size,omitempty"`
	ContinuationToken    string                 `json:"continuation_token,omitempty"`
}

// ListUsersResult holds users as "type:id", usersets as "type:id#relation", or
// the wildcard "type:*". ExcludedUsers are ids a wildcard does not cover.
type ListUsersResult struct {
	Object               string   `json:"object"`
	Users                []string `json:"users"`
	ExcludedUsers        []string `json:"excluded_users"`
	ContinuationToken    *string  `json:"continuation_token"`
	AuthorizationModelID string   `json:"authorization_model_id"`
	ConsistencyToken     string   `json:"consistency_token,omitempty"`
}

// ReadChangesParams pages through the tuple changes feed. PageSize is 1-100
// (default 50); StartTime is RFC 3339.
type ReadChangesParams struct {
	Type              string
	PageSize          int
	ContinuationToken string
	StartTime         string
}

// TupleChange is one entry of the changes feed; Operation is "write" or "delete".
type TupleChange struct {
	Object           string     `json:"object"`
	Operation        string     `json:"operation"`
	User             string     `json:"user"`
	Relation         string     `json:"relation"`
	Target           string     `json:"target"`
	Condition        *Condition `json:"condition,omitempty"`
	ConsistencyToken string     `json:"consistency_token"`
	CreatedAt        int64      `json:"created_at"` // epoch ms
}

// ChangesPage is a page of the changes feed. ContinuationToken is returned even
// on the last page; pass it later to receive only newer changes.
type ChangesPage struct {
	Object            string        `json:"object"`
	Data              []TupleChange `json:"data"`
	HasMore           bool          `json:"has_more"`
	ContinuationToken string        `json:"continuation_token"`
}

// ExpandParams expands the full userset tree for an object#relation.
type ExpandParams struct {
	Object               string `json:"object"`
	Relation             string `json:"relation"`
	AuthorizationModelID string `json:"authorization_model_id,omitempty"`
}

// ExpandResult is the expand tree.
type ExpandResult struct {
	Object               string      `json:"object"`
	Tree                 interface{} `json:"tree"`
	AuthorizationModelID string      `json:"authorization_model_id"`
}

// BatchCheckItem is one item in a batch check.
type BatchCheckItem struct {
	User             string     `json:"user"`
	Relation         string     `json:"relation"`
	Object           string     `json:"object"`
	CorrelationID    string     `json:"correlation_id,omitempty"`
	ContextualTuples []TupleKey `json:"contextual_tuples,omitempty"`
	// Context supplies this item's request-time condition values.
	Context map[string]interface{} `json:"context,omitempty"`
}

// BatchCheckParams is the body of a batch check (<=100 items).
type BatchCheckParams struct {
	Checks               []BatchCheckItem `json:"checks"`
	AuthorizationModelID string           `json:"authorization_model_id,omitempty"`
	Consistency          string           `json:"consistency,omitempty"`
	ConsistencyToken     string           `json:"consistency_token,omitempty"`
}

// BatchCheckResult is the batch-check verdict set.
type BatchCheckResult struct {
	Object               string `json:"object"`
	AuthorizationModelID string `json:"authorization_model_id"`
	ConsistencyToken     string `json:"consistency_token,omitempty"`
	Result               []struct {
		CorrelationID string `json:"correlation_id"`
		Allowed       bool   `json:"allowed"`
	} `json:"result"`
}

// DeletedStore acknowledges a store deletion.
type DeletedStore struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

/* ---- errors ------------------------------------------------------------ */

// APIErrorDetail is one entry of the Atlas §9.1 error envelope.
type APIErrorDetail struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Param   string                 `json:"param,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// APIError is returned for any non-2xx response.
type APIError struct {
	Status int
	Errors []APIErrorDetail
}

func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("atlasfga: %s (HTTP %d)", e.Errors[0].Message, e.Status)
	}
	return fmt.Sprintf("atlasfga: request failed (HTTP %d)", e.Status)
}

// Code returns the first error code, the usual branch point.
func (e *APIError) Code() string {
	if len(e.Errors) > 0 {
		return e.Errors[0].Code
	}
	return ""
}

/* ---- transport --------------------------------------------------------- */

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{Status: resp.StatusCode}
		var env struct {
			Errors []APIErrorDetail `json:"errors"`
		}
		if json.Unmarshal(data, &env) == nil && len(env.Errors) > 0 {
			apiErr.Errors = env.Errors
		} else {
			apiErr.Errors = []APIErrorDetail{{Code: "request_failed", Message: string(data)}}
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) storeOr(explicit string) (string, error) {
	id := explicit
	if id == "" {
		id = c.storeID
	}
	if id == "" {
		return "", fmt.Errorf("atlasfga: no store id (set WithStore / ATLAS_FGA_STORE_ID, or use Client.Store(id))")
	}
	return id, nil
}

func (c *Client) withModel(explicit string) string {
	if explicit == "" {
		return c.modelID
	}
	return explicit
}

/* ---- store-scoped operations (default store) --------------------------- */

// Check resolves a single access question against the default store.
func (c *Client) Check(ctx context.Context, params CheckParams) (*CheckResult, error) {
	return c.CheckIn(ctx, "", params)
}

// CheckIn resolves a single access question against storeID (or the default).
func (c *Client) CheckIn(ctx context.Context, storeID string, params CheckParams) (*CheckResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	params.AuthorizationModelID = c.withModel(params.AuthorizationModelID)
	out := &CheckResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/check", params, out)
}

// Write writes and/or deletes tuples atomically against the default store.
func (c *Client) Write(ctx context.Context, params WriteParams) (*WriteResult, error) {
	return c.WriteIn(ctx, "", params)
}

// WriteIn writes/deletes against storeID (or the default).
func (c *Client) WriteIn(ctx context.Context, storeID string, params WriteParams) (*WriteResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	out := &WriteResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/write", params, out)
}

// WriteTuples is a convenience for Write with only writes.
func (c *Client) WriteTuples(ctx context.Context, writes ...TupleKey) (*WriteResult, error) {
	return c.Write(ctx, WriteParams{Writes: writes})
}

// DeleteTuples is a convenience for Write with only deletes.
func (c *Client) DeleteTuples(ctx context.Context, deletes ...TupleKey) (*WriteResult, error) {
	return c.Write(ctx, WriteParams{Deletes: deletes})
}

// ListObjects lists the objects of a type a user has a relation to.
func (c *Client) ListObjects(ctx context.Context, params ListObjectsParams) (*ListObjectsResult, error) {
	return c.ListObjectsIn(ctx, "", params)
}

// ListObjectsIn lists objects against storeID (or the default).
func (c *Client) ListObjectsIn(ctx context.Context, storeID string, params ListObjectsParams) (*ListObjectsResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	params.AuthorizationModelID = c.withModel(params.AuthorizationModelID)
	out := &ListObjectsResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/list-objects", params, out)
}

// ListUsers lists the users with a relation to an object (one page).
func (c *Client) ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error) {
	return c.ListUsersIn(ctx, "", params)
}

// ListUsersIn lists users against storeID (or the default).
func (c *Client) ListUsersIn(ctx context.Context, storeID string, params ListUsersParams) (*ListUsersResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	params.AuthorizationModelID = c.withModel(params.AuthorizationModelID)
	out := &ListUsersResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/list-users", params, out)
}

// ListAllUsers follows ContinuationToken and merges every page.
func (c *Client) ListAllUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error) {
	return c.ListAllUsersIn(ctx, "", params)
}

// ListAllUsersIn is ListAllUsers against storeID (or the default).
func (c *Client) ListAllUsersIn(ctx context.Context, storeID string, params ListUsersParams) (*ListUsersResult, error) {
	params.ContinuationToken = ""
	merged, err := c.ListUsersIn(ctx, storeID, params)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, u := range merged.ExcludedUsers {
		seen[u] = true
	}
	for merged.ContinuationToken != nil && *merged.ContinuationToken != "" {
		params.ContinuationToken = *merged.ContinuationToken
		page, err := c.ListUsersIn(ctx, storeID, params)
		if err != nil {
			return nil, err
		}
		merged.Users = append(merged.Users, page.Users...)
		for _, u := range page.ExcludedUsers {
			if !seen[u] {
				seen[u] = true
				merged.ExcludedUsers = append(merged.ExcludedUsers, u)
			}
		}
		if page.ConsistencyToken != "" {
			merged.ConsistencyToken = page.ConsistencyToken
		}
		merged.ContinuationToken = page.ContinuationToken
	}
	return merged, nil
}

// ReadChanges reads one page of the tuple changes feed.
func (c *Client) ReadChanges(ctx context.Context, params ReadChangesParams) (*ChangesPage, error) {
	return c.ReadChangesIn(ctx, "", params)
}

// ReadChangesIn reads the changes feed of storeID (or the default).
func (c *Client) ReadChangesIn(ctx context.Context, storeID string, params ReadChangesParams) (*ChangesPage, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if params.Type != "" {
		q.Set("type", params.Type)
	}
	if params.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(params.PageSize))
	}
	if params.ContinuationToken != "" {
		q.Set("continuation_token", params.ContinuationToken)
	}
	if params.StartTime != "" {
		q.Set("start_time", params.StartTime)
	}
	path := "/v1/fga/stores/" + url.PathEscape(id) + "/changes"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	out := &ChangesPage{}
	return out, c.do(ctx, http.MethodGet, path, nil, out)
}

// EachChange calls fn for every change, following pages until HasMore is false.
// It returns the final ContinuationToken (the cursor for next time). fn
// returning an error stops the walk and returns that error.
func (c *Client) EachChange(ctx context.Context, params ReadChangesParams, fn func(TupleChange) error) (string, error) {
	for {
		page, err := c.ReadChanges(ctx, params)
		if err != nil {
			return "", err
		}
		for _, ch := range page.Data {
			if err := fn(ch); err != nil {
				return "", err
			}
		}
		if !page.HasMore {
			return page.ContinuationToken, nil
		}
		params.ContinuationToken = page.ContinuationToken
	}
}

// Read queries stored tuples against the default store.
func (c *Client) Read(ctx context.Context, params ReadParams) (*ListPage[Tuple], error) {
	return c.ReadIn(ctx, "", params)
}

// ReadIn queries tuples against storeID (or the default).
func (c *Client) ReadIn(ctx context.Context, storeID string, params ReadParams) (*ListPage[Tuple], error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	out := &ListPage[Tuple]{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/read", params, out)
}

// Expand expands the full userset tree for an object#relation.
func (c *Client) Expand(ctx context.Context, params ExpandParams) (*ExpandResult, error) {
	return c.ExpandIn(ctx, "", params)
}

// ExpandIn expands against storeID (or the default).
func (c *Client) ExpandIn(ctx context.Context, storeID string, params ExpandParams) (*ExpandResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	params.AuthorizationModelID = c.withModel(params.AuthorizationModelID)
	out := &ExpandResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/expand", params, out)
}

// BatchCheck resolves many access questions in one round trip.
func (c *Client) BatchCheck(ctx context.Context, params BatchCheckParams) (*BatchCheckResult, error) {
	return c.BatchCheckIn(ctx, "", params)
}

// BatchCheckIn resolves a batch against storeID (or the default).
func (c *Client) BatchCheckIn(ctx context.Context, storeID string, params BatchCheckParams) (*BatchCheckResult, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	params.AuthorizationModelID = c.withModel(params.AuthorizationModelID)
	out := &BatchCheckResult{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/batch-check", params, out)
}

/* ---- stores ------------------------------------------------------------ */

// ListStores lists the caller's stores.
func (c *Client) ListStores(ctx context.Context) (*ListPage[Store], error) {
	out := &ListPage[Store]{}
	return out, c.do(ctx, http.MethodGet, "/v1/fga/stores", nil, out)
}

// CreateStore creates a store.
func (c *Client) CreateStore(ctx context.Context, name string) (*Store, error) {
	out := &Store{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores", map[string]string{"name": name}, out)
}

// GetStore fetches a store by id.
func (c *Client) GetStore(ctx context.Context, id string) (*Store, error) {
	out := &Store{}
	return out, c.do(ctx, http.MethodGet, "/v1/fga/stores/"+url.PathEscape(id), nil, out)
}

// DeleteStore removes a store.
func (c *Client) DeleteStore(ctx context.Context, id string) (*DeletedStore, error) {
	out := &DeletedStore{}
	return out, c.do(ctx, http.MethodDelete, "/v1/fga/stores/"+url.PathEscape(id), nil, out)
}

/* ---- authorization models ---------------------------------------------- */

// ListModels lists a store's authorization models.
func (c *Client) ListModels(ctx context.Context, storeID string) (*ListPage[AuthorizationModel], error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	out := &ListPage[AuthorizationModel]{}
	return out, c.do(ctx, http.MethodGet, "/v1/fga/stores/"+url.PathEscape(id)+"/authorization-models", nil, out)
}

// CreateModel persists a new authorization model and returns it.
func (c *Client) CreateModel(ctx context.Context, storeID string, input AuthorizationModelInput) (*AuthorizationModel, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	out := &AuthorizationModel{}
	return out, c.do(ctx, http.MethodPost, "/v1/fga/stores/"+url.PathEscape(id)+"/authorization-models", input, out)
}

// GetModel fetches one authorization model by id.
func (c *Client) GetModel(ctx context.Context, storeID, modelID string) (*AuthorizationModel, error) {
	id, err := c.storeOr(storeID)
	if err != nil {
		return nil, err
	}
	out := &AuthorizationModel{}
	return out, c.do(ctx, http.MethodGet, "/v1/fga/stores/"+url.PathEscape(id)+"/authorization-models/"+url.PathEscape(modelID), nil, out)
}

/* ---- bound store ------------------------------------------------------- */

// BoundStore is a Client with a fixed store id, OpenFGA-SDK style.
type BoundStore struct {
	c       *Client
	storeID string
}

// Store binds storeID for a scope of calls.
func (c *Client) Store(storeID string) *BoundStore { return &BoundStore{c: c, storeID: storeID} }

func (b *BoundStore) Check(ctx context.Context, p CheckParams) (*CheckResult, error) {
	return b.c.CheckIn(ctx, b.storeID, p)
}
func (b *BoundStore) Write(ctx context.Context, p WriteParams) (*WriteResult, error) {
	return b.c.WriteIn(ctx, b.storeID, p)
}
func (b *BoundStore) ListObjects(ctx context.Context, p ListObjectsParams) (*ListObjectsResult, error) {
	return b.c.ListObjectsIn(ctx, b.storeID, p)
}
func (b *BoundStore) ListUsers(ctx context.Context, p ListUsersParams) (*ListUsersResult, error) {
	return b.c.ListUsersIn(ctx, b.storeID, p)
}
func (b *BoundStore) ListAllUsers(ctx context.Context, p ListUsersParams) (*ListUsersResult, error) {
	return b.c.ListAllUsersIn(ctx, b.storeID, p)
}
func (b *BoundStore) ReadChanges(ctx context.Context, p ReadChangesParams) (*ChangesPage, error) {
	return b.c.ReadChangesIn(ctx, b.storeID, p)
}
func (b *BoundStore) Read(ctx context.Context, p ReadParams) (*ListPage[Tuple], error) {
	return b.c.ReadIn(ctx, b.storeID, p)
}
func (b *BoundStore) Expand(ctx context.Context, p ExpandParams) (*ExpandResult, error) {
	return b.c.ExpandIn(ctx, b.storeID, p)
}
func (b *BoundStore) BatchCheck(ctx context.Context, p BatchCheckParams) (*BatchCheckResult, error) {
	return b.c.BatchCheckIn(ctx, b.storeID, p)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
