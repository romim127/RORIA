from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _free_port(start: int = 8765) -> int:
    for port in range(start, start + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return 0


def _open_browser(port: int) -> None:
    time.sleep(2.5)
    webbrowser.open(f"http://127.0.0.1:{port}/red-operativa")


def main() -> None:
    base = _base_dir()
    data_dir = base / "datos"
    data_dir.mkdir(parents=True, exist_ok=True)

    os.chdir(base)
    os.environ.setdefault("SKYEYE_DATA_DIR", str(data_dir))
    os.environ.setdefault("SKYEYE_BOOTSTRAP_SAMPLE", "0")
    os.environ.setdefault("SKYEYE_RELATIONAL_STANDALONE", "1")

    if str(base) not in sys.path:
        sys.path.insert(0, str(base))

    port = _free_port()
    if not port:
        raise RuntimeError("No se encontro un puerto local libre para iniciar Red Operativa Relacional.")

    from red_operativa_app import app
    import uvicorn

    threading.Thread(target=_open_browser, args=(port,), daemon=True).start()
    print("=" * 72)
    print("RED OPERATIVA RELACIONAL")
    print(f"URL local: http://127.0.0.1:{port}/red-operativa")
    print(f"Datos locales: {data_dir}")
    print("Cierra esta ventana para detener el servicio local.")
    print("=" * 72)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
