 # Windows Registry Auditing Module

## Module Structure

The module consists of the following components:

- `scripts/`: Main script and orchestration logic.
- `utils/`: Utilities for file handling and registry interaction.
- `input/`: Directory for input files containing key information.
- `reports/`: Directory for generated reports.

## Usage

The module is designed for audit and investigation purposes, providing insights into Windows Registry keys and permissions without altering the registry itself. It can be enhanced by incorporating the powerful memory analysis capabilities of the Volatility 3 framework.

## File Directory

- `scripts/`: Contains the core script that coordinates the audit process.
- `utils/`: Holds utility scripts for file management and registry interaction.
- `input/`: Place your input files here, including:
  - `admin_editable_keys.txt`: Admin editable keys from previous steps.
  - `system_only_keys.txt`: Keys editable by SYSTEM account.
- `reports/`: Output directory for generated reports.

## File Descriptions

### `scripts/main.py`

Main script orchestrating the audit process:
- Reads input files from `input/` directory.
- Identifies modified keys using `identify_modified_keys`.
- Analyzes permissions using `analyze_permissions` and identifies changes.
- Generates and saves reports with `generate_and_write_report`.

### `utils/file_utils.py`

Utilities for file handling:
- `read_lines_from_file(file_path)`: Reads lines from a file.
- `write_lines_to_file(file_path, lines)`: Writes lines to a file.
- Used by `main.py` for input and output operations.

### `utils/registry_utils.py`

Utilities for Windows Registry interaction:
- `initialize_registry_api()`: Initializes Volatility 3's registry API.
- `retrieve_key_permissions(registry, key)`: Retrieves permissions for a key.
- Used by `main.py` for analyzing permissions.

## Prerequisites

- Python 3.x
- Volatility 3
- Basic understanding of Windows Registry structure and permissions
- Familiarity with Windows PowerShell for advanced permissions analysis

## Getting Started

1. Clone this repository to your local machine.
2. Install Volatility 3 following the instructions provided in their repository: [Volatility 3 Repository](https://github.com/volatilityfoundation/volatility3).
3. Configure the appropriate context and memory image within Volatility 3.
4. Place input files in the `input/` directory.
5. Run the `main.py` script to initiate the audit process.

## Enhancing Analysis with Volatility 3

By integrating the Volatility 3 framework's `windows.registry` module, you can leverage powerful memory analysis capabilities to enhance your audit results. The following example demonstrates how to use Volatility 3 for registry analysis:

1. Load the appropriate context using the context configuration file.

2. Configure the memory image file and Volatility configuration.

3. Initialize the Volatility 3 registry API using `initialize_registry_api()`.

4. Implement placeholder logic in the `analyze_permissions` function to retrieve permissions information using `retrieve_key_permissions`.

5. Use the permissions information to identify permission changes within keys.

### Example Volatility 3 Integration 

```python
from volatility3.framework import contexts
from volatility3.plugins.windows.registry import registryapi

# Load and configure the context and memory image
context_path = "/path/to/Volatility3/volatility3/plugins/overlays/windows/context.yaml"
context = contexts.Context(context_path)

# Set memory image and Volatility configuration
memory_image_path = "/path/to/memory.raw"
volatility_config_path = "/path/to/Volatility3/volatility3/plugins/overlays/windows/windows.json"
context.config['memory_file'] = memory_image_path
context.config['location'] = volatility_config_path

# Initialize the registry API using initialize_registry_api()
registry = initialize_registry_api()

# Implement placeholder logic to retrieve permissions and identify changes
# Analyze permissions for keys using retrieve_key_permissions
