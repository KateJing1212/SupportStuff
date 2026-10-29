"""Start the complete local backend application."""
import os

try:
    from .app import create_app
except ImportError:
    from app import create_app


def main():
    host = os.environ.get("BACKEND_HOST", os.environ.get("F2_HOST", "127.0.0.1"))
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError("本地后端当前仅允许绑定本机回环地址")
    port = int(os.environ.get("BACKEND_PORT", os.environ.get("F2_PORT", "5001")))
    app = create_app()
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
