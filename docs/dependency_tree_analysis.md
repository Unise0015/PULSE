# Dependency Tree & Blast Radius Analysis

PULSE analyzes dependency graphs to distinguish between direct root dependencies and deep transitive sub-dependencies.

---

## 1. Direct vs. Transitive Dependencies

- **Direct Dependencies:** Explicitly declared in top-level project manifests (e.g. `dependencies` in `package.json`, `install_requires` in `setup.py`).
- **Transitive Dependencies:** Indirect dependencies pulled in by parent packages.
- **Blast Radius:** Measures the number of dependent packages impacted by a single vulnerable library in the dependency graph.

---

## 2. Lockfile Parsing & Integrity
PULSE prioritizes locked manifests (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `go.sum`, `composer.lock`) to ensure scans analyze the exact installed release rather than loose SemVer ranges.\n