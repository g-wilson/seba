package token

type Mock struct{}

func (t *Mock) Generate(l int) (string, error) {
	return "mocktoken", nil
}
