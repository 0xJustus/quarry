// Runs attacker-controlled reproducers; the enclosing microVM is the boundary.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type runSpecJSON struct {
	Binary    string   `json:"binary,omitempty"`
	TargetB64 string   `json:"target_b64,omitempty"`
	Image     string   `json:"image,omitempty"`
	Argv      []string `json:"argv"`
	Sanitizer string   `json:"sanitizer,omitempty"`
	StdinPoV  bool     `json:"stdin_pov,omitempty"`
	NoPoV     bool     `json:"nopov,omitempty"`
	TimeoutS  int      `json:"timeout_s,omitempty"`
}

type vetRequest struct {
	ArtifactID string       `json:"artifact_id"`
	Oracle     oracle.Spec  `json:"oracle"`
	Run        runSpecJSON  `json:"run"`
	PoVBase64  string       `json:"pov_b64"`
	Fixed      *runSpecJSON `json:"fixed,omitempty"`
}

type vetResponse struct {
	ArtifactID string         `json:"artifact_id"`
	Admitted   bool           `json:"admitted"`
	Verdict    oracle.Verdict `json:"verdict"`
	Detail     string         `json:"detail,omitempty"`
}

func main() {
	oneshot := flag.Bool("oneshot", false, "run one vet job from stdin (or $QUARRY_VET_REQUEST_B64/file), print the verdict JSON, exit — the per-PoV Fly Machine mode")
	flag.Parse()

	if *oneshot {
		runOneshot()
		return
	}

	addr := ":" + envOr("PORT", "8080")
	token := os.Getenv("VET_TOKEN")
	if token == "" {
		log.Fatal("quarry-vetd: VET_TOKEN is required (or --oneshot for per-PoV Machine mode)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/vet", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req vetRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, code := vetOne(r.Context(), req)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("quarry-vetd listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func runOneshot() {
	var raw []byte
	var err error
	switch {
	case os.Getenv("QUARRY_VET_REQUEST_B64") != "":
		// Fly Machines have no shared filesystem: the job arrives base64 in the env.
		raw, err = base64.StdEncoding.DecodeString(os.Getenv("QUARRY_VET_REQUEST_B64"))
	case os.Getenv("QUARRY_VET_REQUEST") != "":
		raw, err = os.ReadFile(os.Getenv("QUARRY_VET_REQUEST"))
	default:
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	}
	if err != nil {
		log.Fatalf("oneshot: read request: %v", err)
	}
	resp, exit := oneshotResult(context.Background(), raw)
	enc, _ := json.Marshal(resp)
	fmt.Println(string(enc))
	os.Exit(exit)
}

// exit code is the dispatcher's channel; keep in sync with quarry.vetOutcome
func oneshotResult(ctx context.Context, raw []byte) (vetResponse, int) {
	var req vetRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return vetResponse{Detail: "parse request: " + err.Error()}, 1
	}
	resp, code := vetOne(ctx, req)
	switch {
	case code != http.StatusOK:
		return resp, 1 // infra error, never the observation "did not reproduce"
	case resp.Admitted:
		return resp, 0
	default:
		return resp, 3
	}
}

func vetOne(ctx context.Context, req vetRequest) (vetResponse, int) {
	resp := vetResponse{ArtifactID: req.ArtifactID}
	if err := req.Oracle.Validate(); err != nil {
		resp.Detail = "invalid oracle: " + err.Error()
		return resp, http.StatusUnprocessableEntity
	}
	pov, err := base64.StdEncoding.DecodeString(req.PoVBase64)
	if err != nil {
		resp.Detail = "bad pov_b64: " + err.Error()
		return resp, http.StatusBadRequest
	}

	cleanup, err := materializeTargets(&req)
	defer cleanup()
	if err != nil {
		resp.Detail = err.Error()
		return resp, http.StatusBadRequest
	}

	rn, base, err := toRunner(req.Run)
	if err != nil {
		resp.Detail = err.Error()
		return resp, http.StatusBadRequest
	}
	var fixed *runner.RunSpec
	if req.Fixed != nil {
		_, fx, err := toRunner(*req.Fixed)
		if err != nil {
			resp.Detail = "fixed: " + err.Error()
			return resp, http.StatusBadRequest
		}
		fixed = &fx
	}

	// no Store: vetting must not persist; the commons records admission
	v := &verify.Verifier{Runner: rn}
	res, err := v.Verify(ctx, verify.Request{
		Model: "vetd",
		Spec:  req.Oracle,
		Base:  base,
		Fixed: fixed,
		PoV:   pov,
	})
	if err != nil {
		resp.Detail = "vet run failed: " + err.Error()
		return resp, http.StatusInternalServerError
	}
	resp.Verdict = res.Verdict
	resp.Admitted = res.Verdict.Pass
	return resp, http.StatusOK
}

func toRunner(rs runSpecJSON) (runner.Runner, runner.RunSpec, error) {
	spec := runner.RunSpec{
		ArgvTmpl:  rs.Argv,
		Sanitizer: rs.Sanitizer,
		StdinPoV:  rs.StdinPoV,
		NoPoV:     rs.NoPoV,
		Timeout:   time.Duration(rs.TimeoutS) * time.Second,
	}
	switch {
	case rs.Image != "":
		spec.Image = rs.Image
		return runner.DockerRunner{}, spec, nil
	case rs.Binary != "":
		spec.Binary = rs.Binary
		spec.IsolateNetwork = true // untrusted reproducer: no egress
		return runner.LocalRunner{}, spec, nil
	default:
		return nil, spec, fmt.Errorf("run: one of binary or image is required")
	}
}

func materializeTargets(req *vetRequest) (func(), error) {
	var paths []string
	cleanup := func() {
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}
	write := func(rs *runSpecJSON) error {
		if rs == nil || rs.TargetB64 == "" {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(rs.TargetB64)
		if err != nil {
			return fmt.Errorf("bad target_b64: %w", err)
		}
		f, err := os.CreateTemp("", "quarry-target-*")
		if err != nil {
			return err
		}
		path := f.Name()
		paths = append(paths, path)
		if _, err := f.Write(raw); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
		rs.Binary = path
		return nil
	}
	if err := write(&req.Run); err != nil {
		return cleanup, err
	}
	if err := write(req.Fixed); err != nil {
		return cleanup, err
	}
	return cleanup, nil
}

func authorized(r *http.Request, token string) bool {
	got := r.Header.Get("Authorization")
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
