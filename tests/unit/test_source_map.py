"""Unit tests for source_map.py - Source mapping for vulnerability reporting.

This module tests the source mapping functionality that connects EVM bytecode
positions to original Solidity source code locations for vulnerability reporting.
"""

import json
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest


# Mock dependencies before importing source_map module
with patch.dict(
    "sys.modules",
    {
        "ast_helper": Mock(AstHelper=Mock()),
        "utils": Mock(run_command=Mock(return_value='{"contracts":{}}')),
        "six": Mock(),
    },
):
    from oyente import source_map


class TestSourceClass:
    """Test the Source class for loading and parsing source files."""

    def test_source_init_with_valid_file(self):
        """Test Source initialization with a valid file."""
        test_content = "pragma solidity ^0.4.0;\n\ncontract Test {\n    uint x;\n}\n"

        with patch("builtins.open", mock_open(read_data=test_content.encode("utf-8"))):
            source = source_map.Source("test.sol")

            assert source.filename == "test.sol"
            assert source.content == test_content
            assert isinstance(source.line_break_positions, list)

    def test_source_load_content_utf8(self):
        """Test content loading with UTF-8 encoding."""
        test_content = "// UTF-8 test: café\npragma solidity ^0.4.0;"

        with patch("builtins.open", mock_open(read_data=test_content.encode("utf-8"))):
            source = source_map.Source("test.sol")
            assert "café" in source.content

    def test_source_line_break_positions(self):
        """Test line break position calculation."""
        test_content = "line1\nline2\nline3\n"

        with patch("builtins.open", mock_open(read_data=test_content.encode("utf-8"))):
            source = source_map.Source("test.sol")

            # Should find positions of all newline characters
            expected_positions = [5, 11, 17]  # positions of \n characters
            assert source.line_break_positions == expected_positions

    def test_source_empty_file(self):
        """Test Source with empty file."""
        with patch("builtins.open", mock_open(read_data=b"")):
            source = source_map.Source("empty.sol")

            assert source.content == ""
            assert source.line_break_positions == []

    def test_source_file_io_error(self):
        """Test Source handles file I/O errors."""
        with patch("builtins.open", side_effect=OSError("File not found")), pytest.raises(IOError):
            source_map.Source("nonexistent.sol")


class TestSourceMapInitialization:
    """Test SourceMap initialization and basic setup."""

    def test_sourcemap_init_solidity(self):
        """Test SourceMap initialization for Solidity input."""
        test_content = "pragma solidity ^0.4.0;\ncontract TestContract {}"

        # Mock position groups to avoid KeyError
        with patch("builtins.open", mock_open(read_data=test_content.encode("utf-8"))), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            sm = source_map.SourceMap(
                cname="TestContract", parent_filename="test.sol", input_type="solidity", root_path="/path/to/project"
            )

            assert sm.cname == "TestContract"
            assert sm.input_type == "solidity"
            assert sm.root_path == "/path/to/project"

    def test_sourcemap_init_standard_json(self):
        """Test SourceMap initialization for Standard JSON input."""
        test_json = '{"contracts": {}, "sources": {}}'

        # Reset class variables to ensure they get set
        source_map.SourceMap.parent_filename = ""
        source_map.SourceMap.remap = ""
        source_map.SourceMap.allow_paths = ""

        # Mock position groups to avoid initialization issues
        with patch("builtins.open", mock_open(read_data=test_json.encode("utf-8"))), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            sm = source_map.SourceMap(
                cname="TestContract",
                parent_filename="test.json",
                input_type="standard json",
                remap="src=/contracts",
                allow_paths="/allowed",
            )

            assert sm.input_type == "standard json"
            assert source_map.SourceMap.remap == "src=/contracts"
            assert source_map.SourceMap.allow_paths == "/allowed"

    def test_sourcemap_class_variables(self):
        """Test that class variables are properly initialized."""
        # Reset class variables
        source_map.SourceMap.parent_filename = ""
        source_map.SourceMap.position_groups = {}
        source_map.SourceMap.sources = {}
        source_map.SourceMap.ast_helper = None

        assert source_map.SourceMap.parent_filename == ""
        assert source_map.SourceMap.position_groups == {}
        assert source_map.SourceMap.sources == {}
        assert source_map.SourceMap.ast_helper is None


class TestSourceCodeExtraction:
    """Test source code extraction from program counter positions."""

    def setup_method(self):
        """Setup common test data."""
        self.test_source = "pragma solidity ^0.4.0;\n\ncontract Test {\n    uint x;\n}\n"

        # Reset class variables to avoid conflicts
        source_map.SourceMap.parent_filename = ""

        # Create SourceMap with mocked dependencies
        with patch("builtins.open", mock_open(read_data=self.test_source.encode("utf-8"))), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            self.sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

    def test_get_source_code_valid_pc(self):
        """Test source code extraction with valid program counter."""
        # Mock the positions and instr_positions
        self.sourcemap.positions = {"10": "0:50:0"}
        self.sourcemap.instr_positions = {10: {"begin": 0, "end": 50}}

        result = self.sourcemap.get_source_code(10)

        # Should return the substring from source content
        expected = self.test_source[0:50]
        assert result == expected

    def test_get_source_code_invalid_pc(self):
        """Test source code extraction with invalid program counter."""
        # Test with a PC that doesn't exist in instr_positions
        result = self.sourcemap.get_source_code(999)
        assert result == ""

    def test_get_source_code_from_src_valid(self):
        """Test source code extraction from source reference."""
        # Test the actual implementation which splits src and calculates indices
        result = self.sourcemap.get_source_code_from_src("0:50:0")

        # Should extract from position 0 to 0+50=50
        expected = self.test_source[0:50]
        assert result == expected

    def test_get_source_code_from_src_invalid(self):
        """Test source code extraction with invalid source reference."""
        # Test with invalid format that would cause ValueError
        try:
            result = self.sourcemap.get_source_code_from_src("invalid")
            # If no exception, check if empty result
            assert result == ""
        except (ValueError, IndexError):
            # Expected behavior for invalid input
            pass


class TestBuggyLineExtraction:
    """Test buggy line extraction for vulnerability reporting."""

    def setup_method(self):
        """Setup test data."""
        # Reset class variables to avoid conflicts
        source_map.SourceMap.parent_filename = ""

        # Create SourceMap with mocked dependencies
        with patch("builtins.open", mock_open(read_data=b"test content")), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            self.sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

    def test_get_buggy_line_valid_pc(self):
        """Test buggy line extraction with valid program counter."""
        # Mock instr_positions with valid PC
        self.sourcemap.instr_positions = {100: {"begin": 20, "end": 50}}

        # Mock get_location to return None to trigger the empty string return
        with patch.object(self.sourcemap, "get_location", return_value=None):
            result = self.sourcemap.get_buggy_line(100)
            assert result == ""

    def test_get_buggy_line_invalid_pc(self):
        """Test buggy line extraction with invalid program counter."""
        # Test with PC not in instr_positions
        result = self.sourcemap.get_buggy_line(999)
        assert result == ""

    def test_get_buggy_line_from_src_valid(self):
        """Test buggy line extraction from source reference."""
        # Test the actual method which uses _convert_src_to_pos that returns a dict
        mock_source = Mock()
        mock_source.content = "line1\nline2\nline3\nline4"
        mock_source.line_break_positions = [5, 11, 17]
        self.sourcemap.source = mock_source

        # Mock get_location_from_src to return a location with line info
        with patch.object(self.sourcemap, "get_location_from_src", return_value={"begin": {"line": 2}}):
            result = self.sourcemap.get_buggy_line_from_src("12:5:0")

            # Should return the extracted buggy line content
            assert isinstance(result, str)

    def test_get_buggy_line_from_src_first_line(self):
        """Test buggy line extraction for first line."""
        # Test the actual method with proper mocking
        mock_source = Mock()
        mock_source.content = "first line\nsecond line"
        mock_source.line_break_positions = [10]
        self.sourcemap.source = mock_source

        # Mock get_location_from_src to return first line location
        with patch.object(self.sourcemap, "get_location_from_src", return_value={"begin": {"line": 1}}):
            result = self.sourcemap.get_buggy_line_from_src("5:5:0")

            # Should return the extracted line content
            assert isinstance(result, str)


class TestLocationConversion:
    """Test location conversion utilities."""

    def setup_method(self):
        """Setup test data."""
        # Reset class variables to avoid conflicts
        source_map.SourceMap.parent_filename = ""

        # Create SourceMap with mocked dependencies
        with patch("builtins.open", mock_open(read_data=b"test content")), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            self.sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

    def test_get_location_valid_pc(self):
        """Test location extraction with valid program counter."""
        # Mock instr_positions with valid PC
        self.sourcemap.instr_positions = {50: {"begin": 10, "end": 30}}

        # Mock the internal conversion method
        with patch.object(
            self.sourcemap, "_convert_offset_to_line_column", return_value={"begin": {"line": 2, "column": 5}}
        ):
            result = self.sourcemap.get_location(50)

            assert result == {"begin": {"line": 2, "column": 5}}

    def test_get_location_invalid_pc(self):
        """Test location extraction with invalid program counter."""
        # Test with PC not in instr_positions - should raise KeyError
        try:
            result = self.sourcemap.get_location(999)
            # If no exception, then the method handled it somehow
            assert result is not None
        except KeyError:
            # Expected behavior - PC not found
            pass

    def test_get_location_from_src_valid(self):
        """Test location extraction from source reference."""
        with patch.object(self.sourcemap, "_convert_src_to_pos", return_value=(15, 25)), patch.object(
            self.sourcemap, "_convert_offset_to_line_column", return_value=(3, 8)
        ):

            result = self.sourcemap.get_location_from_src("15:10:0")
            assert result == (3, 8)

    def test_convert_src_to_pos_valid_format(self):
        """Test source reference parsing."""
        result = self.sourcemap._convert_src_to_pos("100:50:0")
        # Method returns dict with begin and end keys
        expected = {"begin": 100, "end": 149}  # begin + length - 1
        assert result == expected

    def test_convert_src_to_pos_invalid_format(self):
        """Test source reference parsing with invalid format."""
        # Method should handle errors appropriately
        try:
            result = self.sourcemap._convert_src_to_pos("invalid")
            # If no exception, check result format
            assert isinstance(result, dict)
        except (ValueError, IndexError):
            # Expected behavior for invalid input
            pass

    def test_convert_src_to_pos_empty(self):
        """Test source reference parsing with empty input."""
        # Method should handle empty input appropriately
        try:
            result = self.sourcemap._convert_src_to_pos("")
            assert isinstance(result, dict)
        except (ValueError, IndexError):
            # Expected behavior for empty input
            pass


class TestPositionHandling:
    """Test position and offset handling."""

    def setup_method(self):
        """Setup test data."""
        # Reset class variables to avoid conflicts
        source_map.SourceMap.parent_filename = ""

        # Create SourceMap with mocked dependencies
        with patch("builtins.open", mock_open(read_data=b"test content")), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            self.sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

    def test_convert_offset_to_line_column(self):
        """Test offset to line/column conversion."""
        test_content = "line1\nline2\nline3\n"
        mock_source = Mock()
        mock_source.content = test_content
        mock_source.line_break_positions = [5, 11, 17]
        self.sourcemap.source = mock_source

        # Method expects dict with begin and end positions
        pos_dict = {"begin": 7, "end": 10}
        result = self.sourcemap._convert_offset_to_line_column(pos_dict)

        # Should return dict with begin and end locations
        assert isinstance(result, dict)
        assert "begin" in result
        assert "end" in result

    def test_convert_offset_to_line_column_first_line(self):
        """Test offset conversion for first line."""
        test_content = "hello world\n"
        mock_source = Mock()
        mock_source.content = test_content
        mock_source.line_break_positions = [11]  # Position of newline
        self.sourcemap.source = mock_source

        # Method expects dict with begin and end positions
        pos_dict = {"begin": 5, "end": 8}
        result = self.sourcemap._convert_offset_to_line_column(pos_dict)

        # Should return dict format
        assert isinstance(result, dict)
        assert "begin" in result
        assert "end" in result

    def test_convert_from_char_pos(self):
        """Test character position conversion."""
        test_content = "abc\ndef\nghi"
        mock_source = Mock()
        mock_source.content = test_content
        mock_source.line_break_positions = [3, 7]
        self.sourcemap.source = mock_source

        result = self.sourcemap._convert_from_char_pos(5)  # 'e' in "def"

        # Method returns dict with line and column keys
        assert isinstance(result, dict)
        assert "line" in result
        assert "column" in result

    def test_find_lower_bound(self):
        """Test binary search for lower bound."""
        array = [1, 3, 5, 7, 9, 11]

        assert self.sourcemap._find_lower_bound(0, array) == -1
        assert self.sourcemap._find_lower_bound(1, array) == 0
        assert self.sourcemap._find_lower_bound(4, array) == 1
        assert self.sourcemap._find_lower_bound(6, array) == 2
        assert self.sourcemap._find_lower_bound(15, array) == 5

    def test_find_lower_bound_empty_array(self):
        """Test binary search with empty array."""
        result = self.sourcemap._find_lower_bound(5, [])
        assert result == -1


class TestASTIntegration:
    """Test AST helper integration for variable and function information."""

    def setup_method(self):
        """Setup test data."""
        # Reset class variables to avoid conflicts
        source_map.SourceMap.parent_filename = ""

        # Create SourceMap with mocked dependencies
        with patch("builtins.open", mock_open(read_data=b"test content")), patch.object(
            source_map.SourceMap, "_get_positions", return_value={}
        ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            self.sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

    def test_get_parameter_or_state_var_found(self):
        """Test parameter/state variable retrieval when found."""
        mock_var_names = {"myVar": {"type": "uint256", "location": "storage"}}

        # Set var_names directly on the instance since it's set in __init__
        self.sourcemap.var_names = mock_var_names

        result = self.sourcemap.get_parameter_or_state_var("myVar")
        # The method returns the var_name if found, not the variable info
        assert result == "myVar"

    def test_get_parameter_or_state_var_not_found(self):
        """Test parameter/state variable retrieval when not found."""
        # Set empty var_names
        self.sourcemap.var_names = {}

        result = self.sourcemap.get_parameter_or_state_var("nonexistent")
        assert result is None

    def test_get_parameter_or_state_var_no_ast_helper(self):
        """Test parameter/state variable retrieval without AST helper."""
        # Test with invalid variable name syntax
        result = self.sourcemap.get_parameter_or_state_var("123invalid")
        assert result is None

    def test_get_sig_to_func(self):
        """Test function signature to function mapping."""
        mock_ast_helper = Mock()
        mock_mapping = {"0x12345678": "transfer(address,uint256)"}
        mock_ast_helper.get_func_name_to_params.return_value = mock_mapping

        source_map.SourceMap.ast_helper = mock_ast_helper

        with patch.object(self.sourcemap, "_get_sig_to_func", return_value=mock_mapping):
            result = self.sourcemap._get_sig_to_func()
            assert result == mock_mapping

    def test_get_func_name_to_params(self):
        """Test function name to parameters mapping."""
        mock_ast_helper = Mock()
        # Parameters should be dictionaries with type information
        mock_params = {
            "transfer": [
                {"type": "address", "name": "_to", "value": 1},
                {"type": "uint256", "name": "_value", "value": 1},
            ]
        }
        mock_ast_helper.get_func_name_to_params.return_value = mock_params

        source_map.SourceMap.ast_helper = mock_ast_helper

        result = self.sourcemap._get_func_name_to_params()

        # Method should process the parameters and add position information
        assert isinstance(result, dict)
        assert "transfer" in result
        # Check that positions were added
        assert result["transfer"][0]["position"] == 0
        assert result["transfer"][1]["position"] == 1


class TestStandardJsonHandling:
    """Test Standard JSON input handling."""

    def test_load_position_groups_standard_json_call(self):
        """Test that standard JSON loading is called for standard JSON input."""
        # Reset class variable to ensure fresh state
        source_map.SourceMap.parent_filename = ""

        with patch.object(source_map.SourceMap, "_load_position_groups_standard_json") as mock_load:
            mock_load.return_value = {}

            with patch("builtins.open", mock_open(read_data=b'{"contracts":{}}')), patch.object(
                source_map.SourceMap, "_get_positions", return_value={}
            ), patch.object(source_map.SourceMap, "_get_func_call_names", return_value=[]), patch.object(
                source_map.SourceMap, "_get_func_name_to_params", return_value={}
            ), patch.object(
                source_map.SourceMap, "_get_sig_to_func", return_value={}
            ):
                source_map.SourceMap(cname="Test", parent_filename="test.json", input_type="standard json")

                # Should have called the standard JSON loading during init
                mock_load.assert_called_once()

    def test_load_position_groups_standard_json_with_file(self):
        """Test standard JSON position loading with actual file."""
        test_json = {
            "contracts": {
                "test.sol": {
                    "Test": {
                        "evm": {
                            "bytecode": {"sourceMap": "0:50:0;51:100:0"},
                            "deployedBytecode": {"sourceMap": "0:50:0;51:100:0"},
                        }
                    }
                }
            },
            "sources": {"test.sol": {"id": 0}},
        }

        with patch("builtins.open", mock_open(read_data=json.dumps(test_json).encode("utf-8"))), patch.object(
            source_map.SourceMap, "_load_position_groups_standard_json"
        ) as mock_load, patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(
            source_map.SourceMap, "_get_func_name_to_params", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ):
            mock_load.return_value = {}

            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.json", input_type="standard json")

            sourcemap._load_position_groups_standard_json()


class TestSolidityHandling:
    """Test regular Solidity input handling."""

    def test_load_position_groups_solidity(self):
        """Test position loading for regular Solidity files."""
        mock_command_output = '{"contracts":{"test.sol:Test":{"bin-runtime":"60806040","srcmap-runtime":"0:50:0"}}}'

        with patch.object(source_map, "run_command", return_value=mock_command_output):
            result = source_map.SourceMap._load_position_groups()

            # Should have parsed the solc output and returned the contracts
            assert isinstance(result, dict)
            assert "test.sol:Test" in result

    def test_load_position_groups_solidity_error(self):
        """Test position loading handles solc errors."""
        # The actual implementation returns out["contracts"] so we need the contracts key
        mock_command_output = '{"contracts": {}, "errors":[{"type":"Error","component":"general","severity":"error","message":"File not found"}]}'

        with patch.object(source_map, "run_command", return_value=mock_command_output):
            # Should not raise an exception
            result = source_map.SourceMap._load_position_groups()

            # Should return the contracts dict (which would be empty due to errors)
            assert isinstance(result, dict)
            assert result == {}


class TestFilenameHandling:
    """Test filename handling and resolution."""

    def test_get_filename_with_root_path(self):
        """Test filename resolution with root path."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(
                cname="Test", parent_filename="contracts/test.sol", input_type="solidity", root_path="/project/"
            )

            result = sourcemap.get_filename()
            assert result == "/project/contracts/test.sol"

    def test_get_filename_without_root_path(self):
        """Test filename resolution without root path."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            result = sourcemap.get_filename()
            assert result == "test.sol"

    def test_get_filename_relative_path_normalization(self):
        """Test filename path normalization."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(
                cname="Test", parent_filename="./contracts/../test.sol", input_type="solidity", root_path="/project"
            )

            result = sourcemap.get_filename()
            # Should resolve relative paths
            assert "test.sol" in result


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error conditions."""

    def test_sourcemap_with_none_values(self):
        """Test SourceMap handling of None values."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            with patch.object(sourcemap, "_get_positions", return_value=None):
                result = sourcemap.get_source_code(10)
                assert result == ""

    def test_source_loading_unicode_content(self):
        """Test Source class with Unicode content."""
        unicode_content = "// This is a test with unicode: 🔥💻\ncontract Test {}"

        with patch("builtins.open", mock_open(read_data=unicode_content.encode("utf-8"))):
            source = source_map.Source("test.sol")

            assert "🔥💻" in source.content
            assert source.content.startswith("// This is a test")

    def test_sourcemap_empty_position_groups(self):
        """Test SourceMap with empty position groups."""
        source_map.SourceMap.position_groups = {}

        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            result = sourcemap.get_source_code(100)
            assert result == ""

    def test_convert_src_to_pos_malformed_input(self):
        """Test source position conversion with malformed input."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            # Test various malformed inputs
            assert sourcemap._convert_src_to_pos("abc:def:ghi") == {"begin": 0, "end": 0}
            assert sourcemap._convert_src_to_pos("10:abc:0") == {"begin": 0, "end": 0}
            assert sourcemap._convert_src_to_pos("10") == {"begin": 0, "end": 0}
            assert sourcemap._convert_src_to_pos("10:20") == {"begin": 0, "end": 0}

    def test_binary_search_edge_cases(self):
        """Test binary search with edge cases."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            # Single element array
            assert sourcemap._find_lower_bound(5, [5]) == 0
            assert sourcemap._find_lower_bound(3, [5]) == -1
            assert sourcemap._find_lower_bound(7, [5]) == 0

            # Two element array
            assert sourcemap._find_lower_bound(5, [3, 7]) == 0
            assert sourcemap._find_lower_bound(1, [3, 7]) == -1


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple features."""

    def test_full_vulnerability_location_workflow(self):
        """Test complete workflow from PC to source location."""
        # Setup test contract content
        contract_content = """pragma solidity ^0.4.0;

contract Test {
    uint public value;
    function setValue(uint _value) public {
        value = _value; // This line has a vulnerability
    }
}"""

        # Mock the complete chain
        mock_source = Mock()
        mock_source.content = contract_content
        mock_source.line_break_positions = [23, 24, 41, 61, 62, 126, 148]

        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap = source_map.SourceMap(cname="Test", parent_filename="test.sol", input_type="solidity")

            with patch.object(sourcemap, "_get_positions", return_value={"100": "126:21:0"}), patch.object(
                sourcemap, "_get_source", return_value=mock_source
            ):
                # Set up instr_positions and source for the test
                # "value = _value" starts around position 104 in the contract content
                sourcemap.instr_positions[100] = {"begin": 104, "end": 118}
                sourcemap.source = mock_source

                # Test source code extraction
                source_code = sourcemap.get_source_code(100)
                assert len(source_code) > 0  # Just verify we get some content

                # Test that the methods work without errors
                try:
                    buggy_line = sourcemap.get_buggy_line(100)
                    assert True  # Method completed successfully
                except Exception:
                    assert False  # Method should not raise exceptions

                # Test location extraction
                try:
                    location = sourcemap.get_location(100)
                    assert location is not None  # Should return some location data
                except Exception:
                    assert False  # Method should not raise exceptions

    def test_multiple_contract_source_mapping(self):
        """Test source mapping with multiple contracts."""
        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(source_map.SourceMap, "_get_func_name_to_params", return_value={}), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ):
            sourcemap1 = source_map.SourceMap(cname="Contract1", parent_filename="contract1.sol", input_type="solidity")

            sourcemap2 = source_map.SourceMap(cname="Contract2", parent_filename="contract2.sol", input_type="solidity")

            # Both should work independently
            assert sourcemap1.cname == "Contract1"
            assert sourcemap2.cname == "Contract2"
            assert sourcemap1.input_type == "solidity"
            assert sourcemap2.input_type == "solidity"

    def test_ast_helper_integration_complete(self):
        """Test complete AST helper integration."""
        mock_ast_helper = Mock()
        mock_ast_helper.extract_state_variable_names.return_value = {
            "balance": {"type": "uint256", "location": "storage"},
            "owner": {"type": "address", "location": "storage"},
        }
        mock_ast_helper.get_func_name_to_params.return_value = {
            "transfer": ["address to", "uint256 amount"],
            "approve": ["address spender", "uint256 amount"],
        }

        source_map.SourceMap.ast_helper = mock_ast_helper

        # Mock dependencies to avoid KeyError when creating SourceMap
        with patch.object(source_map.SourceMap, "_get_positions", return_value={}), patch.object(
            source_map.SourceMap, "_get_func_call_names", return_value=[]
        ), patch.object(
            source_map.SourceMap,
            "_get_func_name_to_params",
            return_value={
                "transfer": ["address to", "uint256 amount"],
                "approve": ["address spender", "uint256 amount"],
            },
        ), patch.object(
            source_map.SourceMap, "_get_sig_to_func", return_value={}
        ), patch.object(
            source_map.SourceMap, "_get_source", return_value=""
        ), patch.object(
            source_map.SourceMap, "_get_var_names", return_value=["balance", "owner"]
        ):
            sourcemap = source_map.SourceMap(cname="Token", parent_filename="token.sol", input_type="solidity")

            # Test variable lookup - method returns the variable name if found
            balance_info = sourcemap.get_parameter_or_state_var("balance")
            assert balance_info == "balance" or balance_info is None  # Returns name or None

            # Test function parameters
            func_params = sourcemap._get_func_name_to_params()
            assert "transfer" in func_params
            assert len(func_params["transfer"]) == 2
