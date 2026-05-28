import asyncio
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

load_dotenv()

from orchestrator.graph import run_hunt  # noqa: E402 — must follow load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Threat Hunt Orchestrator starting up")
    yield
    logger.info("Threat Hunt Orchestrator shutting down")


app = FastAPI(title="Threat Hunt Orchestrator", lifespan=lifespan)


class QueryRequest(BaseModel):
    question: str


@app.get("/health")
async def health():
    return {"status": "orchestrator alive"}


@app.post("/api/query")
async def api_query(req: QueryRequest):
    logger.info("Query received (len=%d): %s", len(req.question), req.question[:120])
    try:
        summary = await asyncio.to_thread(run_hunt, req.question)
        return {"summary": summary}
    except Exception as exc:
        logger.exception("Orchestrator error")
        return JSONResponse(status_code=500, content={"error": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
