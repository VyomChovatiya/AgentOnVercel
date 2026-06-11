import http.server
from mock_server import VulnerableSiteHandler
from config import SERVER_HOST, SERVER_PORT

if __name__ == "__main__":
    print(f"🌍 Starting Mock Catalog Server at http://{SERVER_HOST}:{SERVER_PORT}")
    print("Press Ctrl+C to shut it down.")

    server = http.server.HTTPServer((SERVER_HOST, SERVER_PORT), VulnerableSiteHandler)
    server.serve_forever()

