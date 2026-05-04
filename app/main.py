from fastapi import FastAPI
from fastapi.responses import FileResponse
from app.log_reader import start_log_stream
from app.database import init_db
from app.pre_filter import analyze
from app.detector import classify
from app.response_handler import handle
from app.api_routes import router as api_router
import threading

app = FastAPI()                        
app.include_router(api_router)         
@app.get("/")
async def serve_dashboard():
    return FileResponse("static/index.html")

@app.get("/health")
def health_check():
    return {"status": "ok"}

def process_log_line(raw_line: str):
    verdict = analyze(raw_line)
    if not verdict["is_suspicious"]:
        return
    threat = classify(verdict)
    handle(threat)

@app.on_event("startup")
def startup_event():
    init_db()
    thread = threading.Thread(
        target=start_log_stream,
        args=(process_log_line,),
        daemon=True
    )
    thread.start()
    print("[*] Database initialized")
    print("[*] Log stream started in background")