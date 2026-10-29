"""Compatibility launcher. New deployments should use backend/run.py."""
import warnings

try:
    from .run import main
except ImportError:
    from run import main


if __name__ == "__main__":
    warnings.warn(
        "run_f2.py 已弃用；请使用 python backend/run.py 启动完整后端。",
        UserWarning,
    )
    main()
