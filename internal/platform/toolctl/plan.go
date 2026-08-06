package toolctl

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

type BuildPlan struct {
	Name        string
	BuildArgv   []string // docker <BuildArgv...>, assembled but never run here
	Extract     ExtractPlan
	ExpectedPin string
	Prov        Provenance // Hash/Size/BuiltAt stay zero until Populate
}

type ExtractPlan struct {
	Mode      string // ArtifactFile | ArtifactImage
	ImageRef  string
	Path      string // in-image path (ArtifactFile)
	Container string
}

// Argvs is both what --dry-run prints and what extract runs; they must not drift.
func (e ExtractPlan) Argvs(dest string) [][]string {
	if e.Mode == ArtifactImage {
		return [][]string{{"save", "-o", dest, e.ImageRef}}
	}
	return [][]string{
		{"create", "--name", e.Container, e.ImageRef},
		{"cp", e.Container + ":" + e.Path, dest},
		{"rm", "-f", e.Container},
	}
}

// Plan resolves the recipe's relative paths against baseDir.
func (t ToolEntry) Plan(baseDir string) (BuildPlan, error) {
	dockerfile := resolveUnder(baseDir, t.Recipe.Dockerfile)
	context := t.Recipe.Context
	if context == "" {
		context = filepath.Dir(dockerfile)
	} else {
		context = resolveUnder(baseDir, context)
	}

	// sorted build args: a reproducible pin needs a deterministic argv
	build := []string{"build", "-t", t.Recipe.ImageTag, "-f", dockerfile}
	for _, k := range slices.Sorted(maps.Keys(t.Recipe.BuildArgs)) {
		build = append(build, "--build-arg", k+"="+t.Recipe.BuildArgs[k])
	}
	build = append(build, context)

	ex := ExtractPlan{
		Mode:      t.Artifact.mode(),
		ImageRef:  t.Recipe.ImageTag,
		Path:      t.Artifact.Path,
		Container: containerName(t.Name),
	}

	return BuildPlan{
		Name:        t.Name,
		BuildArgv:   build,
		Extract:     ex,
		ExpectedPin: t.Pin,
		Prov: Provenance{
			Name:         t.Name,
			Source:       t.Source,
			Recipe:       t.Recipe,
			ArtifactMode: t.Artifact.mode(),
			ArtifactPath: t.Artifact.Path,
			TargetPath:   t.Artifact.Target,
		},
	}, nil
}

func (m Manifest) Plans(baseDir string) ([]BuildPlan, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	out := make([]BuildPlan, 0, len(m.Tools))
	for _, t := range m.Tools {
		p, err := t.Plan(baseDir)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func resolveUnder(baseDir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

// containerName must be deterministic: create/cp/rm never capture an id.
func containerName(tool string) string {
	var b strings.Builder
	b.WriteString("quarry-toolctl-")
	for _, r := range strings.ToLower(tool) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func Command(dockerBin string, argv []string) string {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	return dockerBin + " " + strings.Join(argv, " ")
}
