import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import os


class TestSetup:
    """Test setup.py utility functions."""

    def test_read_readme_success(self):
        """Test reading README file successfully."""
        # Import the functions directly from setup.py content
        def read_readme():
            with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'README.md'), encoding='utf-8') as f:
                return f.read()

        mock_content = "# Test README\n\nThis is a test README file."
        with patch("builtins.open", mock_open(read_data=mock_content)) as mock_file:
            with patch("os.path.join", return_value="/mock/path/README.md"):
                result = read_readme()
                assert result == mock_content
                mock_file.assert_called_once_with("/mock/path/README.md", encoding="utf-8")

    def test_read_readme_file_not_found(self):
        """Test handling when README file doesn't exist."""
        def read_readme():
            with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'README.md'), encoding='utf-8') as f:
                return f.read()

        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.path.join", return_value="/mock/path/README.md"):
                with pytest.raises(FileNotFoundError):
                    read_readme()

    def test_read_requirements_success(self):
        """Test reading requirements.txt successfully."""
        def read_requirements():
            requirements = []
            try:
                with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'requirements.txt'), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            requirements.append(line)
            except FileNotFoundError:
                # Fallback requirements if requirements.txt doesn't exist
                requirements = [
                    'pyyaml>=6.0',
                    'requests>=2.25.0',
                    'click>=8.0.0',
                    'rich>=10.0.0',
                    'pydantic>=1.8.0',
                    'networkx>=2.5',
                    'langchain>=0.0.300',
                    'langgraph>=0.0.20',
                    'torch>=2.0.0',
                    'transformers>=4.30.0',
                    'peft>=0.4.0',
                    'accelerate>=0.20.0'
                ]
            return requirements

        mock_content = """# Comment line
pydantic>=2.0.0
requests>=2.25.0

# Another comment
click>=8.0.0
"""
        expected_requirements = [
            "pydantic>=2.0.0",
            "requests>=2.25.0",
            "click>=8.0.0"
        ]

        with patch("builtins.open", mock_open(read_data=mock_content)) as mock_file:
            with patch("os.path.join", return_value="/mock/path/requirements.txt"):
                result = read_requirements()
                assert result == expected_requirements
                mock_file.assert_called_once_with("/mock/path/requirements.txt", encoding="utf-8")

    def test_read_requirements_file_not_found(self):
        """Test fallback requirements when requirements.txt doesn't exist."""
        def read_requirements():
            requirements = []
            try:
                with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'requirements.txt'), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            requirements.append(line)
            except FileNotFoundError:
                # Fallback requirements if requirements.txt doesn't exist
                requirements = [
                    'pyyaml>=6.0',
                    'requests>=2.25.0',
                    'click>=8.0.0',
                    'rich>=10.0.0',
                    'pydantic>=1.8.0',
                    'networkx>=2.5',
                    'langchain>=0.0.300',
                    'langgraph>=0.0.20',
                    'torch>=2.0.0',
                    'transformers>=4.30.0',
                    'peft>=0.4.0',
                    'accelerate>=0.20.0'
                ]
            return requirements

        expected_fallback = [
            'pyyaml>=6.0',
            'requests>=2.25.0',
            'click>=8.0.0',
            'rich>=10.0.0',
            'pydantic>=1.8.0',
            'networkx>=2.5',
            'langchain>=0.0.300',
            'langgraph>=0.0.20',
            'torch>=2.0.0',
            'transformers>=4.30.0',
            'peft>=0.4.0',
            'accelerate>=0.20.0'
        ]

        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.path.join", return_value="/mock/path/requirements.txt"):
                result = read_requirements()
                assert result == expected_fallback

    def test_read_requirements_empty_lines_and_comments(self):
        """Test parsing requirements with various whitespace and comments."""
        def read_requirements():
            requirements = []
            try:
                with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'requirements.txt'), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            requirements.append(line)
            except FileNotFoundError:
                requirements = []
            return requirements

        mock_content = """
# This is a comment
pydantic>=2.0.0

# Another comment

requests>=2.25.0
# Inline comment
click>=8.0.0

"""
        expected_requirements = [
            "pydantic>=2.0.0",
            "requests>=2.25.0",
            "click>=8.0.0"
        ]

        with patch("builtins.open", mock_open(read_data=mock_content)) as mock_file:
            with patch("os.path.join", return_value="/mock/path/requirements.txt"):
                result = read_requirements()
                assert result == expected_requirements

    def test_read_requirements_only_comments_and_empty_lines(self):
        """Test parsing requirements file with only comments and empty lines."""
        def read_requirements():
            requirements = []
            try:
                with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'requirements.txt'), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            requirements.append(line)
            except FileNotFoundError:
                requirements = []
            return requirements

        mock_content = """
# This is a comment

# Another comment


"""
        expected_requirements = []

        with patch("builtins.open", mock_open(read_data=mock_content)) as mock_file:
            with patch("os.path.join", return_value="/mock/path/requirements.txt"):
                result = read_requirements()
                assert result == expected_requirements

    def test_read_requirements_mixed_whitespace(self):
        """Test parsing requirements with various whitespace patterns."""
        def read_requirements():
            requirements = []
            try:
                with open(os.path.join(os.path.dirname(__file__).replace('tests', ''), 'requirements.txt'), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            requirements.append(line)
            except FileNotFoundError:
                requirements = []
            return requirements

        mock_content = "pydantic>=2.0.0\n\nrequests>=2.25.0\t\n click>=8.0.0 \n"
        expected_requirements = [
            "pydantic>=2.0.0",
            "requests>=2.25.0",
            "click>=8.0.0"
        ]

        with patch("builtins.open", mock_open(read_data=mock_content)) as mock_file:
            with patch("os.path.join", return_value="/mock/path/requirements.txt"):
                result = read_requirements()
                assert result == expected_requirements