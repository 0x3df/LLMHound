// Package graph defines scoped observation identities and non-traversable graph
// primitives. It performs no network activity, emission or reconciliation.
package graph

import "errors"

const SourceKind = "LLMHound"

// Kind is a logical node kind, independent of adapter qualification.
type Kind string

const (
	Computer                 Kind = "Computer" // Common native kind; native kinds are never source-owned.
	NetworkEndpoint          Kind = "NetworkEndpoint"
	AIService                Kind = "AIService" // Umbrella label; never an identity owner.
	MCPServer                Kind = "MCPServer"
	MCPTool                  Kind = "MCPTool"
	MCPResource              Kind = "MCPResource"
	MCPPrompt                Kind = "MCPPrompt"
	A2AAgent                 Kind = "A2AAgent"
	A2ASkill                 Kind = "A2ASkill"
	OllamaInstance           Kind = "OllamaInstance"
	VLLMInstance             Kind = "VLLMInstance"
	LiteLLMGateway           Kind = "LiteLLMGateway"
	QdrantInstance           Kind = "QdrantInstance"
	MLflowServer             Kind = "MLflowServer"
	JupyterServer            Kind = "JupyterServer"
	OpenWebUIInstance        Kind = "OpenWebUIInstance"
	LangServeApp             Kind = "LangServeApp"
	OpenAICompatibleEndpoint Kind = "OpenAICompatibleEndpoint"
	RayDashboard             Kind = "RayDashboard"
	LangflowInstance         Kind = "LangflowInstance"
	FlowiseInstance          Kind = "FlowiseInstance"
	ChromaInstance           Kind = "ChromaInstance"
	AIModel                  Kind = "AIModel"
	VectorCollection         Kind = "VectorCollection"
	WorkspaceFile            Kind = "WorkspaceFile"
	ModelArtifact            Kind = "ModelArtifact"
	ArtifactStore            Kind = "ArtifactStore"
)

func (k Kind) IsService() bool {
	switch k {
	case MCPServer, A2AAgent, OllamaInstance, VLLMInstance, LiteLLMGateway,
		QdrantInstance, MLflowServer, JupyterServer, OpenWebUIInstance, LangServeApp,
		OpenAICompatibleEndpoint, RayDashboard, LangflowInstance, FlowiseInstance, ChromaInstance:
		return true
	}
	return false
}

func (k Kind) IsResource() bool {
	switch k {
	case MCPTool, MCPResource, MCPPrompt, A2ASkill, AIModel, VectorCollection, WorkspaceFile, ModelArtifact, ArtifactStore:
		return true
	}
	return false
}

// NodeKinds returns source-owned schema kinds, including the umbrella label.
func NodeKinds() []Kind {
	return []Kind{NetworkEndpoint, AIService, MCPServer, MCPTool,
		MCPResource, MCPPrompt, A2AAgent, A2ASkill, OllamaInstance, VLLMInstance,
		LiteLLMGateway, QdrantInstance, MLflowServer, JupyterServer, OpenWebUIInstance,
		LangServeApp, OpenAICompatibleEndpoint, RayDashboard, LangflowInstance,
		FlowiseInstance, ChromaInstance, AIModel, VectorCollection, WorkspaceFile, ModelArtifact, ArtifactStore}
}

// Emitted applies the CE 9.7.1 namespace contract recorded by M0.
func (k Kind) Emitted() (string, error) {
	if k.IsService() || k.IsResource() || k == NetworkEndpoint || k == AIService {
		return SourceKind + "_" + string(k), nil
	}
	return "", errors.New("unknown node kind")
}

// EdgeKind represents evidence or topology, never a v1 attack-path transition.
type EdgeKind string

const (
	ObservedAt       EdgeKind = "ObservedAt"
	RunsOn           EdgeKind = "RunsOn" // Reserved: not inferred from network observations.
	ProvidesTool     EdgeKind = "ProvidesTool"
	ProvidesResource EdgeKind = "ProvidesResource"
	ProvidesPrompt   EdgeKind = "ProvidesPrompt"
	ProvidesModel    EdgeKind = "ProvidesModel"
	AdvertisesSkill  EdgeKind = "AdvertisesSkill"
	UsesBackend      EdgeKind = "UsesBackend"
	Contains         EdgeKind = "Contains"
)

func EdgeKinds() []EdgeKind {
	return []EdgeKind{ObservedAt, RunsOn, ProvidesTool, ProvidesResource, ProvidesPrompt,
		ProvidesModel, AdvertisesSkill, UsesBackend, Contains}
}

func (k EdgeKind) Emitted() (string, error) {
	for _, known := range EdgeKinds() {
		if k == known {
			return SourceKind + "_" + string(k), nil
		}
	}
	return "", errors.New("unknown edge kind")
}

// IsTraversable is false for all kinds, including reserved and unknown kinds.
func (k EdgeKind) IsTraversable() bool { return false }
