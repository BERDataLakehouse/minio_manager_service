"""Tests for the arg_checkers module."""

import pytest

from src.service.arg_checkers import contains_control_characters, not_falsy


class TestNotFalsy:
    """Tests for not_falsy validator."""

    def test_not_falsy_string(self):
        """Test truthy string passes."""
        assert not_falsy("hello", "arg") == "hello"

    def test_not_falsy_number(self):
        """Test truthy number passes."""
        assert not_falsy(42, "arg") == 42

    def test_not_falsy_list(self):
        """Test truthy list passes."""
        assert not_falsy([1], "arg") == [1]

    def test_not_falsy_none_raises(self):
        """Test None raises ValueError."""
        with pytest.raises(ValueError, match="myarg is required"):
            not_falsy(None, "myarg")

    def test_not_falsy_empty_string_raises(self):
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError, match="name is required"):
            not_falsy("", "name")

    def test_not_falsy_zero_raises(self):
        """Test zero raises ValueError."""
        with pytest.raises(ValueError, match="count is required"):
            not_falsy(0, "count")

    def test_not_falsy_empty_list_raises(self):
        """Test empty list raises ValueError."""
        with pytest.raises(ValueError, match="items is required"):
            not_falsy([], "items")


class TestContainsControlCharacters:
    """Tests for contains_control_characters."""

    def test_no_control_chars(self):
        """Test string without control characters."""
        assert contains_control_characters("hello world") == -1

    def test_with_null_byte(self):
        """Test string with null byte."""
        assert contains_control_characters("hello\x00world") == 5

    def test_with_tab(self):
        """Test string with tab character."""
        assert contains_control_characters("hello\tworld") == 5

    def test_with_newline(self):
        """Test string with newline."""
        assert contains_control_characters("hello\nworld") == 5

    def test_allowed_chars(self):
        """Test allowed control characters are ignored."""
        assert contains_control_characters("hello\tworld", ["\t"]) == -1

    def test_allowed_chars_partial(self):
        """Test only specified chars are allowed, others still detected."""
        assert contains_control_characters("a\tb\nc", ["\t"]) == 3

    def test_empty_string(self):
        """Test empty string has no control characters."""
        assert contains_control_characters("") == -1

    def test_returns_first_position(self):
        """Test returns position of first control character."""
        assert contains_control_characters("\x00\x01\x02") == 0
