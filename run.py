import threading
import webbrowser

import uvicorn

from app import app

if __name__ == "__main__":
    url = "http://127.0.0.1:8765"
    print(f"StressScope running at {url}  (Ctrl+C to quit)")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
