import os
import secrets
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.openai_adapter import model_adapter_from_environment
from src.secure_model import secure_generate


bearer = HTTPBearer(auto_error=False)


class RequestSizeLimit:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received_bytes = 0
        chunks = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            received_bytes += len(body)
            if received_bytes > 65536:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        body_pending = True

        async def bounded_receive() -> Message:
            nonlocal body_pending
            if body_pending:
                body_pending = False
                return {"type": "http.request", "body": b"".join(chunks)}
            return await receive()

        await self.app(scope, bounded_receive, send)


def require_api_key(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> None:
    expected = os.environ.get("GATEWAY_API_KEY", "")
    if len(expected) < 32 or expected != expected.strip():
        raise HTTPException(status_code=503, detail="Gateway authentication unavailable")
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid gateway credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


class GatewayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    trusted_user_request: str = Field(min_length=1, max_length=16000)
    untrusted_external_content: str = Field(default="", max_length=16000)
    run_trusted_task_without_external: bool = False

    @field_validator("trusted_user_request")
    @classmethod
    def reject_blank_request(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("A trusted request is required")
        return value


class InputFinding(BaseModel):
    source: str
    categories: list[str]


class InputScreening(BaseModel):
    decision: Literal["ALLOW", "BLOCK"]
    findings: list[InputFinding]


class OutputScreening(BaseModel):
    decision: Literal["ALLOW", "REDACTED", "BLOCK"]
    categories: list[str]


class GatewayResponse(BaseModel):
    final_decision: Literal["ALLOW", "REVIEW", "BLOCK"]
    model_status: str
    model_response: str | None
    forwarded_to_model: bool
    filtered_task_forwarded: bool
    input_screening: InputScreening
    output_screening: OutputScreening | None = None


app = FastAPI(
    title="AI Security Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    dependencies=[Depends(require_api_key)],
)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request, _error):
    return JSONResponse(status_code=422, content={"detail": "Invalid gateway request"})


@app.middleware("http")
async def private_responses(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


app.add_middleware(RequestSizeLimit)


def gateway_response(result: dict) -> GatewayResponse:
    return GatewayResponse(
        final_decision=result["final_decision"],
        model_status=result["model_status"],
        model_response=result["model_response"],
        forwarded_to_model=result["forwarded_to_model"],
        filtered_task_forwarded=result["filtered_task_forwarded"],
        input_screening=result["input_screening"],
        output_screening=result.get("output_screening"),
    )


@app.post("/v1/evaluate", response_model=GatewayResponse)
def evaluate(request: GatewayRequest) -> GatewayResponse:
    return gateway_response(secure_generate(
        request.trusted_user_request,
        request.untrusted_external_content,
    ))


@app.post("/v1/generate", response_model=GatewayResponse)
def generate(request: GatewayRequest) -> GatewayResponse:
    try:
        model = model_adapter_from_environment()
    except Exception:
        raise HTTPException(
            status_code=503, detail="Model configuration unavailable"
        ) from None
    return gateway_response(secure_generate(
        request.trusted_user_request,
        request.untrusted_external_content,
        model=model,
        run_trusted_task_without_external=request.run_trusted_task_without_external,
        security_canary="SYNTHETIC_CANARY_" + secrets.token_hex(24),
    ))