# Security Scanner

A Python-based tool designed to scan files within a directory for potential security vulnerabilities. The scanner checks for hardcoded credentials, insecure HTTP links, SQL injection risks, unsanitized inputs, and missing authentication patterns. It is configurable and supports concurrent file scanning for improved performance.

## Features

- **Pattern Matching**: Detects various security vulnerabilities such as exposed credentials, insecure HTTP usage, unsanitized input functions, and SQL injection patterns.
- **Configurable Patterns**: Allows the use of a custom configuration file to define patterns. If no configuration file is provided or the provided file is invalid, the tool falls back on default patterns.
- **Concurrency**: Utilizes Python's `ThreadPoolExecutor` to scan files concurrently, improving efficiency for directories with many files.
- **Logging**: Detailed logs are written to a log file and displayed in the console, providing insights on the findings during the scan.
- **File Filtering**: Only scans files with specified extensions (e.g., `.py`, `.js`, `.php`, `.html`, etc.) which can be configured via the configuration file.

## Installation

### Requirements

- Python 3.6 or higher is required.
- The script uses Python's built-in libraries: `os`, `re`, `logging`, `json`, and `concurrent.futures`, so no additional dependencies are needed.

### Usage

1. **Clone the Repository** (if applicable):
   ```bash
   git clone https://github.com/fish-hue/Security-Scanner/secscan.git
   cd Security-Scanner
   ```

2. **Run the Scanner**:
   ```bash
   python sescan.py <directory-to-scan> --config <path-to-config.json> --logfile <path-to-logfile.log>
   ```

   - `<directory-to-scan>`: Path to the directory you want to scan.
   - `--config`: Path to a custom JSON configuration file (optional). If not provided, the script will use default patterns.
   - `--logfile`: Path to the log file (optional). The default is `security_scan.log`.

### Example

```bash
python secscan.py /path/to/your/project --config /path/to/config.json --logfile security_scan.log
```

This will scan the directory `/path/to/your/project` for vulnerabilities and log the results to `security_scan.log`.

## Configuration File

The configuration file allows you to customize the patterns to search for. Here's an example of how the `config.json` file should look:

### Example of `config.json`

```json
{
  "CREDENTIAL_PATTERNS": ["password", "username", "api_key", "access_token", "secret"],
  "INSECURE_HTTP_PATTERN": "(?i)http://[^\s]+",
  "SQL_PATTERN": "(select|insert|update|delete|drop|union)\\s+[^\s]+.*\\s*=\\s*.*[\"';]",
  "UNSANITIZED_INPUT_PATTERN": "(eval|exec|input|os\\.system|subprocess)\\s*\\(",
  "MISSING_AUTH_PATTERN": "/(admin|dashboard|user|settings)\\s*[^a-zA-Z]",
  "FILE_EXTENSIONS": [".py", ".js", ".html", ".php"]
}
```

### Default Patterns

If no configuration file is provided, the scanner will use the following default patterns:

- **CREDENTIAL_PATTERNS**: Looks for sensitive keywords such as `password`, `username`, `api_key`, `access_token`, and `secret`.
- **INSECURE_HTTP_PATTERN**: Matches URLs starting with `http://` (insecure HTTP).
- **SQL_PATTERN**: Matches SQL injection patterns like `select`, `insert`, `update`, `drop`, etc.
- **UNSANITIZED_INPUT_PATTERN**: Matches risky unsanitized inputs such as `eval`, `exec`, `input`, `os.system`, and `subprocess`.
- **MISSING_AUTH_PATTERN**: Detects potentially insecure paths (e.g., `/admin`, `/dashboard`, `/user`) that may lack proper authentication.

## How It Works

1. **Directory Scan**: The scanner walks through the specified directory and its subdirectories to find files with the extensions defined in the configuration (or defaults).
2. **Pattern Matching**: Each file is scanned line by line to search for defined patterns.
3. **Logging**: If any patterns are found, the script logs the filename, pattern name, line number, and the matching text.
4. **Concurrency**: Multiple files are scanned concurrently using Python's `ThreadPoolExecutor`, making the process more efficient.

## Example Output

If any vulnerabilities are found, the output will be similar to this:

```plaintext
2024-12-17 12:00:00,123 - INFO - Found 3 issues:
2024-12-17 12:00:00,123 - INFO - /path/to/file.py | Pattern: CREDENTIAL_PATTERNS | Line: 42 | Start: 15 | Match: password = "mySecretPassword"
2024-12-17 12:00:00,124 - INFO - /path/to/file.php | Pattern: INSECURE_HTTP_PATTERN | Line: 10 | Start: 5 | Match: http://example.com
2024-12-17 12:00:00,125 - INFO - /path/to/file.js | Pattern: SQL_PATTERN | Line: 75 | Start: 8 | Match: select * from users where username = 'admin'
```

If no issues are found:

```plaintext
2024-12-17 12:00:00,123 - INFO - No security issues found.
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

