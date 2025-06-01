package models

// Dependency represents a JavaScript dependency
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string   `json:"id,omitempty"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"`
	References  []string `json:"references,omitempty"`
	CVEID       string   `json:"cve_id,omitempty"`
	Fix         string   `json:"fix,omitempty"`
}

// Framework represents a detected JavaScript framework
type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

// AnalysisResult represents the result of a JavaScript analysis
type AnalysisResult struct {
	Target          *Target          `json:"target"`
	Dependencies    []*Dependency    `json:"dependencies,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities,omitempty"`
	Frameworks      []*Framework     `json:"frameworks,omitempty"`
	IsMinified      bool             `json:"is_minified"`
	BundleType      string           `json:"bundle_type,omitempty"`
	FileSize        int64            `json:"file_size,omitempty"`
	ScriptCount     int              `json:"script_count,omitempty"`
	Duration        string           `json:"duration,omitempty"`
}

// NewAnalysisResult creates a new analysis result
func NewAnalysisResult(target *Target) *AnalysisResult {
	return &AnalysisResult{
		Target:          target,
		Dependencies:    []*Dependency{},
		Vulnerabilities: []*Vulnerability{},
		Frameworks:      []*Framework{},
	}
}

// AddDependency adds a dependency to the analysis result
func (r *AnalysisResult) AddDependency(name, version string) *AnalysisResult {
	r.Dependencies = append(r.Dependencies, &Dependency{
		Name:    name,
		Version: version,
	})
	return r
}

// AddVulnerability adds a vulnerability to the analysis result
func (r *AnalysisResult) AddVulnerability(vulnType, severity, description, location string) *AnalysisResult {
	r.Vulnerabilities = append(r.Vulnerabilities, &Vulnerability{
		Type:        vulnType,
		Severity:    severity,
		Description: description,
		Location:    location,
	})
	return r
}

// AddFramework adds a framework to the analysis result
func (r *AnalysisResult) AddFramework(name, version string) *AnalysisResult {
	r.Frameworks = append(r.Frameworks, &Framework{
		Name:    name,
		Version: version,
	})
	return r
}

// SetBundleType sets the bundle type
func (r *AnalysisResult) SetBundleType(bundleType string) *AnalysisResult {
	r.BundleType = bundleType
	return r
}

// SetIsMinified sets whether the script is minified
func (r *AnalysisResult) SetIsMinified(isMinified bool) *AnalysisResult {
	r.IsMinified = isMinified
	return r
}

// SetFileSize sets the file size
func (r *AnalysisResult) SetFileSize(size int64) *AnalysisResult {
	r.FileSize = size
	return r
}

// SetScriptCount sets the script count
func (r *AnalysisResult) SetScriptCount(count int) *AnalysisResult {
	r.ScriptCount = count
	return r
}

// SetDuration sets the analysis duration
func (r *AnalysisResult) SetDuration(duration string) *AnalysisResult {
	r.Duration = duration
	return r
}
