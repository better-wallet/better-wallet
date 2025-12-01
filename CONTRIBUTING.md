# Contributing to Better Wallet

Thank you for your interest in contributing to Better Wallet! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 15+
- Git
- Basic understanding of blockchain/wallet concepts

### Setting Up Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/better-wallet.git
   cd better-wallet
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/better-wallet/better-wallet.git
   ```

4. Install dependencies:
   ```bash
   go mod download
   ```

5. Set up the database:
   ```bash
   createdb better_wallet_dev
   cd dashboard
   bun install
   DATABASE_URL=postgres://user:pass@localhost:5432/better_wallet_dev bun run db:push
   cd ..
   ```

6. Copy the example environment file and configure it:
   ```bash
   cp .env.example .env
   # Edit .env with your development settings
   ```

## Development Workflow

### Creating a Branch

Always create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

### Making Changes

1. Make your changes in your feature branch
2. Write or update tests as needed
3. Ensure all tests pass:
   ```bash
   go test ./...
   ```
4. Format your code:
   ```bash
   go fmt ./...
   ```

### Code Style

- Follow standard Go conventions and idioms
- Use meaningful variable and function names
- Write clear comments for complex logic
- Keep functions focused and reasonably sized
- Use English for all code and comments

### Commit Messages

Write clear, concise commit messages:

```
feat: add session signer support

- Implement session signer creation API
- Add TTL and policy override functionality
- Include audit logging for signer operations
```

Format:
- First line: Brief summary (50 chars or less)
- Blank line
- Detailed description if needed

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test updates
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### Testing

All code contributions should include tests:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/policy
```

### Pull Requests

1. Update your branch with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Create a Pull Request on GitHub with:
   - Clear title describing the change
   - Description of what changed and why
   - Reference to any related issues
   - Screenshots/examples if applicable

4. Wait for review and address any feedback

## Project Structure

Understanding the project structure will help you contribute effectively:

```
better-wallet/
├── cmd/server/          # Application entry point
├── internal/
│   ├── api/             # HTTP handlers
│   ├── app/             # Business logic
│   ├── config/          # Configuration
│   ├── crypto/          # Cryptographic utilities
│   ├── keyexec/         # Key execution backends
│   ├── middleware/      # HTTP middleware
│   ├── policy/          # Policy engine
│   └── storage/         # Database layer
├── pkg/                 # Public packages
├── dashboard/           # Next.js dashboard (manages DB schema)
└── docs/                # Documentation
```

## Areas for Contribution

### High Priority

- Additional chain support (Solana, Bitcoin, etc.)
- Enhanced policy conditions
- Performance optimizations
- Security improvements
- Documentation improvements

### Good First Issues

Look for issues tagged with `good first issue` on GitHub.

## Reporting Bugs

When reporting bugs, please include:

- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Go version, etc.)
- Relevant logs or error messages

## Suggesting Features

For feature requests:

- Check existing issues first
- Provide clear use case and rationale
- Describe the proposed solution
- Consider backwards compatibility

## Security Vulnerabilities

**Do not** report security vulnerabilities through public GitHub issues.

Instead, email security@better-wallet.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Documentation

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add examples or tutorials
- Improve API documentation
- Translate documentation (future)

## Questions?

- GitHub Discussions for general questions
- Discord for real-time help
- GitHub Issues for bugs and features

## License

By contributing to Better Wallet, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to Better Wallet! 🚀
