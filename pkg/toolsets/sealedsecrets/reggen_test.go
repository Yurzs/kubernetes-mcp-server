package sealedsecrets

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ReggenSuite struct {
	suite.Suite
}

func (s *ReggenSuite) TestGenerateFromPattern() {
	s.Run("alphanumeric 32 chars", func() {
		result, err := generateFromPattern("[a-zA-Z0-9]{32}")
		s.Require().NoError(err)
		s.Len(result, 32)
		s.Regexp(regexp.MustCompile(`^[a-zA-Z0-9]{32}$`), result)
	})

	s.Run("hex 64 chars", func() {
		result, err := generateFromPattern("[a-f0-9]{64}")
		s.Require().NoError(err)
		s.Len(result, 64)
		s.Regexp(regexp.MustCompile(`^[a-f0-9]{64}$`), result)
	})

	s.Run("prefixed key", func() {
		result, err := generateFromPattern("sk_live_\\w{24}")
		s.Require().NoError(err)
		s.True(len(result) == 8+24, "expected 32 chars, got %d", len(result))
		s.Regexp(regexp.MustCompile(`^sk_live_[a-zA-Z0-9_]{24}$`), result)
	})

	s.Run("literal characters only", func() {
		result, err := generateFromPattern("hello")
		s.Require().NoError(err)
		s.Equal("hello", result)
	})

	s.Run("special characters in class", func() {
		result, err := generateFromPattern("[!@#$%]{8}")
		s.Require().NoError(err)
		s.Len(result, 8)
		s.Regexp(regexp.MustCompile(`^[!@#$%]{8}$`), result)
	})

	s.Run("digit shorthand", func() {
		result, err := generateFromPattern("\\d{6}")
		s.Require().NoError(err)
		s.Len(result, 6)
		s.Regexp(regexp.MustCompile(`^\d{6}$`), result)
	})

	s.Run("range repetition", func() {
		result, err := generateFromPattern("[a-z]{8,16}")
		s.Require().NoError(err)
		s.True(len(result) >= 8 && len(result) <= 16,
			"expected length 8-16, got %d", len(result))
		s.Regexp(regexp.MustCompile(`^[a-z]+$`), result)
	})

	s.Run("dot any char", func() {
		result, err := generateFromPattern(".{10}")
		s.Require().NoError(err)
		s.Len(result, 10)
	})

	s.Run("mixed literal and pattern", func() {
		result, err := generateFromPattern("prefix_[a-z]{4}_suffix")
		s.Require().NoError(err)
		s.Regexp(regexp.MustCompile(`^prefix_[a-z]{4}_suffix$`), result)
	})

	s.Run("single char no repetition", func() {
		result, err := generateFromPattern("[a-z]")
		s.Require().NoError(err)
		s.Len(result, 1)
		s.Regexp(regexp.MustCompile(`^[a-z]$`), result)
	})
}

func (s *ReggenSuite) TestGenerateFromPatternErrors() {
	s.Run("unclosed character class", func() {
		_, err := generateFromPattern("[abc")
		s.Error(err)
		s.Contains(err.Error(), "unclosed character class")
	})

	s.Run("unclosed repetition", func() {
		_, err := generateFromPattern("[a-z]{3")
		s.Error(err)
		s.Contains(err.Error(), "unclosed repetition")
	})

	s.Run("invalid range", func() {
		_, err := generateFromPattern("[z-a]{3}")
		s.Error(err)
		s.Contains(err.Error(), "invalid range")
	})

	s.Run("repetition exceeds max", func() {
		_, err := generateFromPattern("[a-z]{2000}")
		s.Error(err)
		s.Contains(err.Error(), "exceeds maximum")
	})
}

func (s *ReggenSuite) TestRandomnessIsUnique() {
	s.Run("two generated values differ", func() {
		a, err := generateFromPattern("[a-zA-Z0-9]{32}")
		s.Require().NoError(err)
		b, err := generateFromPattern("[a-zA-Z0-9]{32}")
		s.Require().NoError(err)
		// With 32 chars from 62 options, collision probability is negligible
		s.NotEqual(a, b, "two independently generated values should differ")
	})
}

func TestReggen(t *testing.T) {
	suite.Run(t, new(ReggenSuite))
}
