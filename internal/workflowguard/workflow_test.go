package workflowguard

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const publicationGate = "${{ github.event_name == 'workflow_dispatch' && inputs.publish == true }}"

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

type job struct {
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
}

func loadWorkflows(t *testing.T) map[string]workflow {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	directory := filepath.Join(filepath.Dir(filename), "../../.github/workflows")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	workflows := make(map[string]workflow)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var parsed workflow
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		workflows[entry.Name()] = parsed
	}
	return workflows
}

// Validate the complete workflow set: adding an automatic or reusable workflow
// requires a policy review, rather than silently creating a publication bypass.
func validate(workflows map[string]workflow) error {
	if len(workflows) != 1 {
		return fmt.Errorf("unexpected workflow set")
	}
	w, ok := workflows["build.yml"]
	if !ok || len(w.On) != 1 {
		return fmt.Errorf("unexpected workflow or event")
	}
	dispatch, ok := w.On["workflow_dispatch"].(map[string]any)
	if !ok {
		return fmt.Errorf("manual dispatch missing")
	}
	inputs, ok := dispatch["inputs"].(map[string]any)
	if !ok || len(inputs) != 1 {
		return fmt.Errorf("unexpected dispatch inputs")
	}
	confirmation, ok := inputs["publish"].(map[string]any)
	if !ok || confirmation["type"] != "boolean" || confirmation["required"] != true || confirmation["default"] != false {
		return fmt.Errorf("confirmation must be a required boolean, default false")
	}
	if !reflect.DeepEqual(w.Permissions, map[string]string{"contents": "read"}) {
		return fmt.Errorf("workflow permissions must be read only")
	}
	if len(w.Jobs) != 12 {
		return fmt.Errorf("unexpected publication job count")
	}
	for name, j := range w.Jobs {
		if j.If != publicationGate {
			return fmt.Errorf("job %s can bypass explicit confirmation", name)
		}
		expected := map[string]string{"contents": "read", "packages": "write"}
		switch name {
		case "build-openai-worker", "build-grok-worker", "build-kiro-reg", "build-gemini-reg", "build-ts-solver":
			expected = map[string]string{"contents": "write"}
		case "deploy-cf-worker":
			expected = nil // inherits read-only workflow permissions
		case "build-app", "build-macmini-openai", "build-macmini-grok", "build-macmini-kiro", "build-macmini-gemini", "build-macmini-ts":
		default:
			return fmt.Errorf("unreviewed publication job %s", name)
		}
		if !reflect.DeepEqual(j.Permissions, expected) {
			return fmt.Errorf("job %s permissions exceed its operation", name)
		}
	}
	return nil
}

func TestPublicationPolicy(t *testing.T) {
	if err := validate(loadWorkflows(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationEventMatrix(t *testing.T) {
	w := loadWorkflows(t)
	if err := validate(w); err != nil {
		t.Fatal(err)
	}
	events := []string{"push", "pull_request", "create", "schedule", "repository_dispatch", "workflow_run", "release", "workflow_dispatch"}
	// The inputs context preserves booleans; a missing value or string "true"
	// must never be treated as an explicit typed-boolean confirmation.
	inputs := []any{nil, false, true, "true"}
	for name, j := range w["build.yml"].Jobs {
		for _, event := range events {
			for _, input := range inputs {
				allowed := j.If == publicationGate && event == "workflow_dispatch" && input == true
				want := event == "workflow_dispatch" && input == true
				if allowed != want {
					t.Fatalf("unexpected eligibility for %s", name)
				}
			}
		}
	}
}

func TestPolicyRejectsPublicationBypasses(t *testing.T) {
	mutations := map[string]func(map[string]workflow){
		"automatic main push": func(ws map[string]workflow) {
			w := ws["build.yml"]
			w.On["push"] = map[string]any{"branches": []any{"main"}}
			ws["build.yml"] = w
		},
		"default confirmation true": func(ws map[string]workflow) {
			ws["build.yml"].On["workflow_dispatch"].(map[string]any)["inputs"].(map[string]any)["publish"].(map[string]any)["default"] = true
		},
		"confirmation string": func(ws map[string]workflow) {
			ws["build.yml"].On["workflow_dispatch"].(map[string]any)["inputs"].(map[string]any)["publish"].(map[string]any)["type"] = "string"
		},
		"unguarded deployment": func(ws map[string]workflow) {
			j := ws["build.yml"].Jobs["deploy-cf-worker"]
			j.If = ""
			ws["build.yml"].Jobs["deploy-cf-worker"] = j
		},
		"OR condition": func(ws map[string]workflow) {
			j := ws["build.yml"].Jobs["build-app"]
			j.If = strings.Replace(publicationGate, "&&", "||", 1)
			ws["build.yml"].Jobs["build-app"] = j
		},
		"write all default permissions": func(ws map[string]workflow) {
			w := ws["build.yml"]
			w.Permissions = map[string]string{"contents": "write"}
			ws["build.yml"] = w
		},
		"new publication job": func(ws map[string]workflow) { ws["build.yml"].Jobs["unguarded"] = job{} },
		"chained workflow":    func(ws map[string]workflow) { ws["publish.yml"] = workflow{On: map[string]any{"workflow_run": nil}} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ws := loadWorkflows(t)
			mutate(ws)
			if validate(ws) == nil {
				t.Fatal("unsafe publication policy accepted")
			}
		})
	}
}
