package hunter

type Finding struct {
	DetectorType string
	Line         int
	Secret       string
	File         string
	Verified     bool
}

type Hunter interface {
	Hunt(source string) ([]Finding, error)
}