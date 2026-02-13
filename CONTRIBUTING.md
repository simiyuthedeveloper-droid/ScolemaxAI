# Contributing to SMV Security WAF

Thank you for your interest in contributing to SMV Security! We welcome contributions from developers, security researchers, and community members worldwide. This document provides guidelines and instructions for contributing.

---

## 🎯 Types of Contributions We Welcome

- 🐛 **Bug Reports** - Help us identify and fix issues
- ✨ **Feature Requests** - Suggest improvements and new capabilities
- 📝 **Documentation** - Improve guides, tutorials, and API docs
- 🔧 **Code Contributions** - Submit bug fixes and new features
- 🧪 **Testing** - Help test new features and identify edge cases
- 🔐 **Security Reports** - Responsibly disclose vulnerabilities
- 🌍 **Localization** - Help translate into other languages
- 💬 **Community** - Answer questions and help other users

---

## Getting Started

### Prerequisites

- **Git** - Version control
- **PHP 7.4+** - For development and testing
- **MySQL/MariaDB 5.7+** - For database
- **cURL** - For API testing
- **Basic understanding of:**
  - Web application security
  - RESTful APIs
  - Database design

### Setting Up Your Development Environment

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/smv-security-waf.git
cd smv-security-waf

# 3. Add upstream remote
git remote add upstream https://github.com/SMVSecurity/smv-security-waf.git

# 4. Create a development branch
git checkout -b feature/your-feature-name

# 5. Set up local development
# Follow README.md for setup instructions

# 6. Create a local database
mysql -u root -p < waf_database.sql
```

---

## 🐛 Reporting Bugs

### Before Submitting a Bug Report

- ✅ Check existing issues to avoid duplicates
- ✅ Verify the bug with the latest code
- ✅ Collect detailed information about the issue

### How to Submit a Bug Report

Use the issue tracker with this information:

```markdown
**Title:** Brief description of the bug

**Description:** Detailed explanation of what's wrong

**Steps to Reproduce:**
1. First step
2. Second step
3. Expected result vs Actual result

**Environment:**
- PHP Version: 8.0
- MySQL Version: 8.0
- WAF Version: 1.0.0
- Server OS: Ubuntu 20.04

**Error Messages/Logs:**
Paste relevant error messages here

**Screenshots:** 
If applicable, add screenshots

**Possible Solution:**
If you have ideas on how to fix it
```

---

## ✨ Requesting Features

### Before Submitting a Feature Request

- ✅ Check if the feature already exists
- ✅ Verify it aligns with the project's goals
- ✅ Consider if it's beneficial to other users

### How to Submit a Feature Request

```markdown
**Title:** Clear title describing the feature

**Problem:** What problem does this solve?

**Proposed Solution:** Detailed description of your idea

**Use Cases:** When and why would users need this?

**Examples:** Code examples or mockups

**Alternatives:** Other solutions you considered
```

---

## 💻 Code Contributions

### Code Style Guidelines

#### PHP
```php
<?php
// Use PSR-12 coding standard
// https://www.php-fig.org/psr/psr-12/

// Class names: PascalCase
class ThreatAnalyzer {
    
    // Method names: camelCase
    public function analyzeThreats() {
        // Implementation
    }
    
    // Constants: SCREAMING_SNAKE_CASE
    const MAX_ANALYSIS_TIME = 30;
}

// Function names: snake_case
function get_threat_data() {
    // Implementation
}

// Variable names: camelCase
$threatLevel = 'critical';
```

#### Documentation
- Use clear, concise language
- Include code examples
- Document all parameters and return values
- Add comments for complex logic

#### Naming Conventions
- Use descriptive names (not `$x` or `$temp`)
- Use prefixes for related functions (`threat_*`, `block_*`)
- Use suffixes for types (`*_array`, `*_string`)

### Git Commit Messages

```
Format: <type>(<scope>): <subject>

<type>: feat, fix, docs, style, refactor, test, chore
<scope>: threatanalyzer, threatblocker, logger, etc.
<subject>: Lowercase, no period, imperative mood

Example:
feat(threatanalyzer): add payload complexity scoring

This improves threat severity calculation by analyzing
the complexity of attack payloads.
```

### Pull Request Process

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature
   ```

2. **Make your changes:**
   - Write clean, well-documented code
   - Follow the code style guidelines
   - Add tests for new features
   - Update documentation

3. **Test thoroughly:**
   ```bash
   # Run tests
   php vendor/bin/phpunit
   
   # Test integration
   php install.php
   ```

4. **Commit with good messages:**
   ```bash
   git commit -m "feat(threatanalyzer): add new scoring logic"
   ```

5. **Push to your fork:**
   ```bash
   git push origin feature/your-feature
   ```

6. **Create a Pull Request:**
   - Reference related issues
   - Describe your changes clearly
   - Include screenshots if applicable
   - Request reviewers

7. **Address review feedback:**
   - Make requested changes
   - Respond to comments
   - Push updates to the same branch

---

## 🔐 Security Vulnerability Reporting

**Do NOT open a public issue for security vulnerabilities!**

Instead, please email:
📧 **security@scolemax.co.ke**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if available)

We will acknowledge receipt within 48 hours and work on a fix.

---

## 📝 Documentation Contributions

### Documentation Areas

- **Installation Guides** - Setup instructions
- **API Documentation** - Endpoint references
- **Configuration Guides** - Setup and customization
- **Troubleshooting** - Common issues and solutions
- **Examples** - Code samples and use cases
- **Architecture Docs** - System design and flow

### How to Contribute Docs

1. Check existing documentation
2. Create a clear, concise guide
3. Include examples and screenshots
4. Follow markdown formatting
5. Submit as a pull request

---

## 🧪 Testing Guidelines

### Required Tests

- ✅ Unit tests for new functions
- ✅ Integration tests for API endpoints
- ✅ Security tests for authentication
- ✅ Performance tests for large datasets

### Running Tests

```bash
# Run all tests
php vendor/bin/phpunit

# Run specific test class
php vendor/bin/phpunit tests/ThreatAnalyzerTest.php

# Run with coverage
php vendor/bin/phpunit --coverage-html coverage/
```

---

## 📋 Pull Request Template

```markdown
## Description
Brief description of changes

## Related Issues
Fixes #123
Related to #456

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Backwards compatible

## Screenshots (if applicable)
Add screenshots here
```

---

## ✅ Code Review Process

1. **Automated Checks:**
   - Code style validation (PSR-12)
   - Syntax checking
   - Security scanning

2. **Manual Review:**
   - At least 1 maintainer review
   - Functionality verification
   - Security assessment
   - Performance check

3. **Approval & Merge:**
   - All checks must pass
   - At least 1 approval required
   - Automatic merge or manual merge by maintainer

---

## 📚 Additional Resources

- **Project Board:** https://github.com/SMVSecurity/smv-security-waf/projects
- **Issue Tracker:** https://github.com/SMVSecurity/smv-security-waf/issues
- **Documentation:** https://threatresponder.scolemax.co.ke/docs/
- **API Reference:** https://threatresponder.scolemax.co.ke/docs.php

---

## 🤝 Community and Support

- **Discussions:** Use GitHub Discussions for questions
- **Email:** community@scolemax.co.ke
- **Website:** https://threatresponder.scolemax.co.ke

---

## 📜 Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

---

## 📄 License

By contributing to SMV Security WAF, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 Thank You!

We appreciate your interest in contributing to SMV Security! Your contributions help make cybersecurity more accessible to organizations in Kenya and beyond.

**Happy coding! 🚀**

---

**Questions?** Contact us at:
- 📧 community@scolemax.co.ke
- 💬 GitHub Discussions
- 🌐 https://threatresponder.scolemax.co.ke

**Version:** 1.0
**Last Updated:** February 10, 2026
