# JOCKY Development Guide

This document outlines how to set up the development environment, run tests, and contribute to the JOCKY project.

## Development Setup

### 1. Create a Virtual Environment

It is highly recommended to use a Python virtual environment to manage dependencies.

```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate
```

### 2. Install in Development Mode

The project uses `pyproject.toml` for dependency management. Install the project along with development dependencies (like `pytest`):

```bash
pip install -e .[dev]
```

### 3. Environment Variables

Create a `.env` file in the root directory. You can use the `.env.example` file as a reference.

```bash
cp .env.example .env
```

Ensure you set a strong `SECRET_KEY` and appropriate `ADMIN_PASSWORD` for initial setup.

## Running the Application

### CLI Usage

You can use the `jocky` command-line tool to verify your environment and run scripts:

```bash
# Verify system dependencies and environment
jocky doctor

# Parse a JOCKY script and view the AST
jocky ast examples/basic_scan.jky

# Compile to LLVM IR (currently produces stub IR)
jocky compile examples/basic_scan.jky

# Run semantic analysis
jocky check examples/basic_scan.jky

# Execute a JOCKY script
jocky run examples/basic_scan.jky
```

### Starting the Backend Server

Start the FastAPI backend server using either of the following commands:

```bash
jocky-server

# Or directly via Python:
python -m backend.app.main
```

## Running Tests

The project uses `pytest` for testing. To run the full test suite:

```bash
pytest
```

## Project Structure

```text
jocky/
├── backend/           # FastAPI web application and database models
├── collectors/        # Forensic evidence gathering modules
├── compiler/          # Lexer, parser, and IR generator for the JOCKY DSL
├── docs/              # Documentation
├── engine/            # Correlation, IOC matching, and timeline logic
├── runtime/           # AST interpreter and command execution
├── tests/             # Unit and integration tests
├── pyproject.toml     # Project metadata and dependencies
└── README.md
```

## Contributing Guidelines

### Adding a New Collector

1. Create a new file in the `collectors/` directory.
2. Implement a class that inherits from a base collector (if applicable) and implements a `collect()` method returning a dictionary of findings.
3. Update `runtime/interpreter.py` (or the relevant registry) to integrate the new collector.
4. Add tests for the new collector in the `tests/` directory.

### Adding a Test

1. Create a test file in the `tests/` directory following the `test_*.py` naming convention.
2. Use `pytest` fixtures for setup and teardown where appropriate.
3. Ensure your test verifies the expected behavior and handles edge cases.

### Code Style Guidelines

*   Follow standard PEP 8 formatting for Python code.
*   Use type hints wherever possible to improve readability and maintainability.
*   Document complex logic and class structures using docstrings.
