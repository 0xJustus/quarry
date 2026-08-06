package artifact

// PublicAbstract is the public sibling: specimen and reproducer stripped, placement forced Public.
func (e *Envelope) PublicAbstract(abstract, createdAt string) *Envelope {
	return &Envelope{
		Artifact: Artifact{
			V: SchemaVersion,
			Content: Content{
				Specimen: nil,
				Crash:    e.Artifact.Content.Crash,
			},
			Reproducer: nil,
		},
		Placement:  Public,
		Abstract:   abstract,
		Provenance: e.Provenance,
		CreatedAt:  createdAt,
	}
}
