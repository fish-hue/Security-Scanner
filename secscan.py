import os
import re
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_FILE_EXTENSIONS = ('.py', '.js', '.java', '.txt', '.conf', '.php')

class SecurityScanner:
    def __init__(self, directory, config=None, log_level=logging.INFO, log_file='security_scan.log'):
        self.directory = directory
        logging.basicConfig(level=log_level, 
                            format='%(asctime)s - %(levelname)s - %(message)s', 
                            handlers=[logging.FileHandler(log_file), logging.StreamHandler()])
        self.patterns = self.load_config_patterns(config)
        self.compiled_patterns = self.compile_patterns(self.patterns)

    def load_config_patterns(self, config):
        """Load patterns from the specified configuration file."""
        if config:
            try:
                with open(config, 'r') as f:
                    loaded_patterns = json.load(f)
                    return self.validate_loaded_patterns(loaded_patterns)
            except (IOError, json.JSONDecodeError) as e:
                logging.error(f"Could not load config file: {e}")
        logging.info("Using default patterns due to missing or invalid config.")
        return self.default_patterns()

    def default_patterns(self):
        """Return default patterns to be used for scanning."""
        return {
            "CREDENTIAL_PATTERNS": ['password', 'username', 'api_key', 'access_token', 'secret'],
            "INSECURE_HTTP_PATTERN": r"(?i)http://[^\s]+",
            "SQL_PATTERN": r'(select|insert|update|delete|drop|union)\s+[^\s]+.*\s*=\s*.*["\';]',
            "UNSANITIZED_INPUT_PATTERN": r'(eval|exec|input|os\.system|subprocess)\s*\(',
            "MISSING_AUTH_PATTERN": r'(/admin|/dashboard|/user|/settings)\s*[^a-zA-Z]',
            "FILE_EXTENSIONS": [".py", ".js", ".html", ".php"]
        }

    def validate_loaded_patterns(self, loaded_patterns):
        """Validate that all essential keys are present in the loaded patterns."""
        essential_keys = ["CREDENTIAL_PATTERNS", "INSECURE_HTTP_PATTERN", "SQL_PATTERN", 
                          "UNSANITIZED_INPUT_PATTERN", "MISSING_AUTH_PATTERN", "FILE_EXTENSIONS"]
        for key in essential_keys:
            if key not in loaded_patterns:
                logging.warning(f"{key} is missing from config; reverting to defaults.")
                loaded_patterns[key] = self.default_patterns()[key]  # Use default if missing
        return loaded_patterns

    def compile_patterns(self, patterns):
        """Compile regex patterns for efficient matching."""
        compiled = {}
        for name, pattern in patterns.items():
            if isinstance(pattern, list):
                compiled[name] = [re.compile(p) for p in pattern]
            else:
                compiled[name] = re.compile(pattern)
        return compiled

    def validate_directory(self):
        """Check if the specified directory is valid."""
        if not os.path.isdir(self.directory):
            logging.error(f"The directory '{self.directory}' is not valid or does not exist.")
            return False
        return True

    def is_valid_file(self, file_name):
        """Check if the file should be scanned based on its extension."""
        return file_name.endswith(tuple(self.patterns["FILE_EXTENSIONS"]))

    def scan_file_for_patterns(self, file_path):
        """Scan a file for all defined patterns and return matches."""
        matches = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, start=1):  # Read file line by line
                    for pattern_name, regex in self.compiled_patterns.items():
                        if isinstance(regex, list):  # For credential patterns
                            for r in regex:
                                matches.extend([(file_path, pattern_name, line_num, m.start(), m.group())
                                                 for m in r.finditer(line)])
                        else:  # For other patterns
                            matches.extend([(file_path, pattern_name, line_num, m.start(), m.group())
                                             for m in regex.finditer(line)])
        except (IOError, UnicodeDecodeError, PermissionError) as e:
            logging.error(f"Error reading file '{file_path}': {e}")
        return matches

    def search_in_directory(self):
        """Search through the provided directory for vulnerable patterns in files."""
        matches = []
        with ThreadPoolExecutor() as executor:
            futures = []
            for subdir, dirs, files in os.walk(self.directory):
                for file in files:
                    if self.is_valid_file(file):
                        file_path = os.path.join(subdir, file)
                        futures.append(executor.submit(self.scan_file_for_patterns, file_path))
            for future in as_completed(futures):
                matches.extend(future.result())
        return matches

    def run(self):
        """Run the security scanner."""
        if not self.validate_directory():
            return

        all_matches = self.search_in_directory()

        if all_matches:
            logging.info(f"Found {len(all_matches)} issues:")
            for file_path, pattern_name, line_num, start_position, matched_text in all_matches:
                logging.info(f"{file_path} | Pattern: {pattern_name} | Line: {line_num} | Start: {start_position} | Match: {matched_text[:50]}")
        else:
            logging.info("No security issues found.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Scan a directory for security vulnerabilities.')
    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('--config', help='Path to config file', default=None)
    parser.add_argument('--logfile', help='Log file path', default='security_scan.log')
    args = parser.parse_args()

    scanner = SecurityScanner(args.directory, config=args.config, log_file=args.logfile)
    scanner.run()
