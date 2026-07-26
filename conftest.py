import os
import sys
import tempfile
from pathlib import Path


def pytest_configure():
    """
    Ensures 'ansible_collections.dettonville.utils' is resolvable
    for bare pytest calls from any location.
    """
    # 1. If already resolvable (e.g., via run-tests.sh), do nothing
    try:
        import ansible_collections.dettonville.utils  # noqa: F401
        return
    except ImportError:
        pass

    # 2. Derive collection repo root (where this root conftest.py lives)
    repo_root = Path(__file__).resolve().parent

    # 3. Build a fixed sandbox structure in /tmp
    tmp_dir = Path(tempfile.gettempdir()) / "ansible_collections_sandbox"
    target_dir = tmp_dir / "ansible_collections" / "dettonville" / "utils"

    target_dir.parent.mkdir(parents=True, exist_ok=True)

    # 4. Create/update symlink pointing to the repository root
    if target_dir.is_symlink() or target_dir.exists():
        if target_dir.resolve() != repo_root.resolve():
            target_dir.unlink()
            os.symlink(repo_root, target_dir)
    else:
        os.symlink(repo_root, target_dir)

    # 5. Inject into sys.path before test collection occurs
    if str(tmp_dir) not in sys.path:
        sys.path.insert(0, str(tmp_dir))
