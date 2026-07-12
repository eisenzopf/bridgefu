//! Authenticated `/v1/calls` handlers over the durable transactional service.

use std::str::FromStr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::CallId;
use bridgefu::call_service::{
    CallService, CallView, CreateCallInput, CreateCallView, DtmfAcceptedView, DtmfCallInput,
    GetCallInput, IdempotencyKey, TransferCallInput,
};

use super::{ApiError, ApiState};

pub(super) async fn create_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    headers: HeaderMap,
    input: Result<Json<CreateCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateCallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let result = service.create_call(&principal, &key, input).await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "create",
        "result" => if result.replayed { "replayed" } else { "created" }
    )
    .increment(1);
    Ok((StatusCode::CREATED, Json(result.value)))
}

pub(super) async fn get_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    Query(input): Query<GetCallInput>,
) -> Result<Json<CallView>, ApiError> {
    let (service, principal) = call_context(&state, principal)?;
    let call_id = parse_call_id(&call_id)?;
    Ok(Json(service.get_call(&principal, call_id, input).await?))
}

pub(super) async fn hangup_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<CallView>), ApiError> {
    let input = parse_optional_json(body)?;
    let (service, principal) = call_context(&state, principal)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let result = service
        .hangup_call(&principal, parse_call_id(&call_id)?, &key, input)
        .await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "hangup",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

pub(super) async fn transfer_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<TransferCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<CallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let result = service
        .transfer_call(&principal, parse_call_id(&call_id)?, &key, input)
        .await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "transfer",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

pub(super) async fn dtmf_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<DtmfCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<DtmfAcceptedView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let result = service
        .send_dtmf(&principal, parse_call_id(&call_id)?, &key, input)
        .await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "dtmf",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

fn call_context(
    state: &ApiState,
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<(Arc<CallService>, ApiPrincipal), ApiError> {
    let service = state.call_service.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call service is not configured",
        )
    })?;
    let principal = principal.map(|value| value.0).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call authentication is not configured",
        )
    })?;
    Ok((service, principal))
}

fn parse_call_id(value: &str) -> Result<CallId, ApiError> {
    CallId::from_str(value).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_call_id",
            "call ID must be a non-nil UUID",
        )
    })
}

fn parse_json<T>(input: Result<Json<T>, JsonRejection>) -> Result<Json<T>, ApiError> {
    input.map_err(|rejection| {
        if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
            return ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "call request body exceeds 65536 bytes",
            );
        }
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body is not valid for this operation",
        )
    })
}

fn parse_optional_json<T>(body: Result<Bytes, BytesRejection>) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned + Default,
{
    let body = body.map_err(|rejection| {
        if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "call request body exceeds 65536 bytes",
            )
        } else {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body could not be read",
            )
        }
    })?;
    if body.is_empty() {
        Ok(T::default())
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "request body is not valid for this operation",
            )
        })
    }
}
