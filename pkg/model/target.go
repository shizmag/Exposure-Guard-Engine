package model

// Target represents the normalized scan target.
type Target struct {
	Raw    string `json:"raw"`
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Domain string `json:"domain"`
}
