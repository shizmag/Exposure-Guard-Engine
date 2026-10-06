package model

// ScanPlan represents the preview execution plan for a scan without executing network requests.
type ScanPlan struct {
	Target        string   `json:"target"`
	Host          string   `json:"host"`
	Scheme        string   `json:"scheme"`
	Profile       string   `json:"profile"`
	Mode          ScanMode `json:"mode"`
	NativeModules []string `json:"native_modules"`
	Integrations  []string `json:"integrations"`
	Limits        Limits   `json:"limits"`
}
