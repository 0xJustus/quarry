package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

// prefixes every route and is echoed in the version header, so skew fails fast
const APIVersion = "v1"

const apiVersionHeader = "Quarry-Api-Version"

const (
	routeCapabilities = "/" + APIVersion + "/capabilities"
	routeOutbox       = "/" + APIVersion + "/outbox"
	routeLookup       = "/" + APIVersion + "/lookup"
	routeUpdates      = "/" + APIVersion + "/updates"
)

type (
	capabilitiesResp struct {
		APIVersion   string `json:"api_version"`
		MaxPlacement string `json:"max_placement"`
	}
	lookupReq struct {
		Keys []string `json:"keys"`
	}
	lookupResp struct {
		PriorArt []PriorArt `json:"prior_art"`
	}
	updateResp struct {
		Has    bool   `json:"has"`
		Update Update `json:"update"`
	}
	errResp struct {
		Error string `json:"error"`
	}
)

// transport only: the local emit gate must have run before Emit
type SyncClient struct {
	BaseURL  string
	BasePath string
	HTTP     *http.Client
	Cap      artifact.Placement
}

func NewSyncClient(baseURL string) *SyncClient {
	return &SyncClient{BaseURL: strings.TrimRight(baseURL, "/"), BasePath: "/quarry", HTTP: http.DefaultClient, Cap: artifact.Public}
}

func (c *SyncClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// BasePath is verbatim: empty means the handler is mounted at the URL root
func (c *SyncClient) endpoint(route string) string {
	return c.BaseURL + c.BasePath + route
}

func (c *SyncClient) MaxPlacement() artifact.Placement { return c.Cap }

// a peer may only narrow this ceiling, never widen it
func (c *SyncClient) Capabilities(ctx context.Context) (artifact.Placement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(routeCapabilities), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(apiVersionHeader, APIVersion)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("sync: capabilities: %w", err)
	}
	defer resp.Body.Close()
	if err := checkResp(resp); err != nil {
		return "", err
	}
	var out capabilitiesResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("sync: capabilities decode: %w", err)
	}
	p := artifact.Placement(out.MaxPlacement)
	if !p.Valid() {
		return "", fmt.Errorf("sync: capabilities: peer advertised invalid placement %q", out.MaxPlacement)
	}
	if p.Rank() < c.Cap.Rank() {
		c.Cap = p
	}
	return c.Cap, nil
}

func (c *SyncClient) Emit(ctx context.Context, e *artifact.Envelope) error {
	if e == nil {
		return fmt.Errorf("sync: nil envelope")
	}
	// fail closed: Rank() reads an unknown ceiling as the most permissive
	if !c.Cap.Valid() {
		return fmt.Errorf("sync: client ceiling %q is not a valid placement; refusing to emit", c.Cap)
	}
	if e.Placement.Rank() > c.Cap.Rank() {
		return fmt.Errorf("sync: placement %q exceeds client ceiling %q", e.Placement, c.Cap)
	}
	wire, err := e.Marshal()
	if err != nil {
		return fmt.Errorf("sync: marshal envelope: %w", err)
	}
	resp, err := c.post(ctx, routeOutbox, wire)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResp(resp)
}

func (c *SyncClient) Lookup(ctx context.Context, keys []string) ([]PriorArt, error) {
	body, err := json.Marshal(lookupReq{Keys: keys})
	if err != nil {
		return nil, err
	}
	resp, err := c.post(ctx, routeLookup, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResp(resp); err != nil {
		return nil, err
	}
	var out lookupResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("sync: lookup decode: %w", err)
	}
	return out.PriorArt, nil
}

func (c *SyncClient) Pull(ctx context.Context, sinceVersion string) (Update, bool, error) {
	u := c.endpoint(routeUpdates) + "?since=" + url.QueryEscape(sinceVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Update{}, false, err
	}
	req.Header.Set(apiVersionHeader, APIVersion)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Update{}, false, fmt.Errorf("sync: pull: %w", err)
	}
	defer resp.Body.Close()
	if err := checkResp(resp); err != nil {
		return Update{}, false, err
	}
	var out updateResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Update{}, false, fmt.Errorf("sync: pull decode: %w", err)
	}
	return out.Update, out.Has, nil
}

func (c *SyncClient) post(ctx context.Context, route string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(route), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(apiVersionHeader, APIVersion)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sync: %s: %w", route, err)
	}
	return resp, nil
}

func checkResp(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var er errResp
	if json.Unmarshal(b, &er) == nil && er.Error != "" {
		return fmt.Errorf("sync: server %d: %s", resp.StatusCode, er.Error)
	}
	return fmt.Errorf("sync: server %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
}

// a nil Source/Feed degrades that read route to an empty answer; a nil Sink 503s
type SyncHandler struct {
	Sink   ArtifactSink
	Source PatternSource
	Feed   UpdateFeed
}

func (h *SyncHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(routeCapabilities, h.handleCapabilities)
	mux.HandleFunc(routeOutbox, h.handleOutbox)
	mux.HandleFunc(routeLookup, h.handleLookup)
	mux.HandleFunc(routeUpdates, h.handleUpdates)
	return versionGuard(mux)
}

func versionGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(apiVersionHeader, APIVersion)
		if v := r.Header.Get(apiVersionHeader); v != "" && v != APIVersion {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("unsupported api version %q (want %q)", v, APIVersion))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *SyncHandler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	cap := artifact.Public
	if h.Sink != nil {
		cap = h.Sink.MaxPlacement()
	}
	writeJSON(w, http.StatusOK, capabilitiesResp{APIVersion: APIVersion, MaxPlacement: string(cap)})
}

func (h *SyncHandler) handleOutbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	e, err := artifact.Unmarshal(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "decode envelope: "+err.Error())
		return
	}
	// never trust the wire: the server re-verifies
	if err := e.Verify(); err != nil {
		writeErr(w, http.StatusBadRequest, "verify envelope: "+err.Error())
		return
	}
	if h.Sink == nil {
		// fail closed: a 2xx here marks the item synced and drops it from the outbox
		writeErr(w, http.StatusServiceUnavailable, "outbox: no sink configured on this peer")
		return
	}
	if e.Placement.Rank() > h.Sink.MaxPlacement().Rank() {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("placement %q exceeds sink capacity %q", e.Placement, h.Sink.MaxPlacement()))
		return
	}
	if err := h.Sink.Emit(r.Context(), e); err != nil {
		writeErr(w, http.StatusInternalServerError, "sink: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SyncHandler) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req lookupReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	if h.Source == nil {
		writeJSON(w, http.StatusOK, lookupResp{})
		return
	}
	hits, err := h.Source.Lookup(r.Context(), req.Keys)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lookupResp{PriorArt: hits})
}

func (h *SyncHandler) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	if h.Feed == nil {
		writeJSON(w, http.StatusOK, updateResp{Has: false})
		return
	}
	up, has, err := h.Feed.Pull(r.Context(), r.URL.Query().Get("since"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pull: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updateResp{Has: has, Update: up})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errResp{Error: msg})
}

var (
	_ ArtifactSink  = (*SyncClient)(nil)
	_ PatternSource = (*SyncClient)(nil)
	_ UpdateFeed    = (*SyncClient)(nil)
)
