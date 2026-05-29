# GlobiGuard .NET SDK - Development Guide

## CI/CD Pipeline Overview

This repository uses GitHub Actions for automated testing, building, and publishing.

### Workflows

#### 1. **Test & Lint** (`test.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Builds with .NET 9.0
  - Runs all tests via `dotnet test`
  - Reports test results
- **Status check:** ✅ Must pass before merging to `main`

#### 2. **Build & Package** (`build.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Packs NuGet package (.nupkg)
  - Verifies package integrity
  - Uploads to GitHub Artifacts
- **Purpose:** Verify package creation before publish

#### 3. **Publish** (`publish.yml`)
- **Triggers:** When a git tag matching `v*.*.*` is pushed
- **What it does:**
  - Builds NuGet package
  - Publishes to NuGet.org
  - Creates GitHub Release
- **Requirements:** `NUGET_API_KEY` secret configured
- **Usage:**
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

#### 4. **Security Scan** (`security.yml`)
- **Triggers:** Every push to `main`/`develop`, weekly on Sunday
- **What it does:**
  - Checks for vulnerable dependencies
  - Runs Roslyn analyzers
- **Purpose:** Continuous security monitoring

### Branch Protection

The `main` branch is protected with:
- ✅ Require 1 pull request review before merging
- ✅ Require all status checks to pass
- ✅ Require branches to be up to date before merging
- ✅ Dismiss stale pull request approvals on new commits
- ✅ Require code owner reviews
- ❌ Force pushes disabled
- ❌ Deletions disabled

### Versioning Strategy

We use **Semantic Versioning** (major.minor.patch):

- **0.1.0** → Initial release
- **0.1.1** → Patch fix
- **0.2.0** → Minor feature
- **1.0.0** → Major release (breaking changes)

Update version in `.csproj`:
```xml
<Version>0.1.0</Version>
```

### Publishing Workflow

```bash
# 1. Make changes on a feature branch
git checkout -b feat/new-feature
git commit -m "feat: new feature"

# 2. Update version if needed
# Edit src/GlobiGuard/GlobiGuard.csproj:
# <Version>0.2.0</Version>
git commit -m "bump: version to 0.2.0"

# 3. Push and create PR
git push origin feat/new-feature

# 4. Review, merge to main

# 5. Tag release
git tag v0.1.0
git push origin v0.1.0

# 6. Watch CI/CD publish to NuGet
# dotnet add package GlobiGuard
```

### Development Cycle

1. **Create feature branch:** `git checkout -b feature/name main`
2. **Make changes:** Edit code, test locally
3. **Run tests locally:** `dotnet test`
4. **Commit:** `git commit -m "feat: description"`
5. **Push:** `git push origin feature/name`
6. **Create PR:** Open GitHub pull request to `main`
7. **Review:** Automated tests and code review
8. **Merge:** Merge PR to `main`
9. **Publish (optional):** Update version and tag

### Local Testing

```bash
# Restore dependencies
dotnet restore

# Build
dotnet build

# Run tests
dotnet test

# Build release package
dotnet pack --configuration Release

# Verify NuGet package
dotnet nuget verify dist/*.nupkg
```

### Code Owners

Code ownership is defined in `.github/CODEOWNERS`:
- All files: `@globi-explore/maintainers`
- PRs require approval from code owners before merge

### Repository Configuration

- **Default branch:** `main`
- **Discussions:** Enabled (for Q&A)
- **Releases:** Auto-generated from tags
- **Topics:** `globiguard`, `sdk`, `governance`, `dotnet`, `csharp`
- **Visibility:** Public
- **.NET version:** 9.0
- **Language features:** Nullable reference types enabled

## Troubleshooting

**Build fails?**
- Clear build cache: `dotnet clean`
- Restore packages: `dotnet restore`
- Check .NET SDK: `dotnet --version`

**Tests fail?**
- Run individually: `dotnet test --filter "TestClass"`
- Check diagnostics: `dotnet test --logger "console;verbosity=detailed"`

**NuGet publish fails?**
- Verify API key is valid
- Check version doesn't already exist on NuGet.org
- Ensure `.csproj` configuration is correct

## Questions?

See main repository README or GitHub Discussions for Q&A.
