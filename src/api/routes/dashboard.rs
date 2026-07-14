use crate::api::errors::ApiError;
use crate::api::response::ApiResponse;
use crate::auth::AuthContext;
use crate::state::AppState;
use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct DashboardResponse {
    pub total_projects: i64,
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub medium_findings: i64,
    pub average_score: f64,
    pub recent_scans: Vec<RecentScan>,
    pub findings_by_severity: Vec<SeverityCount>,
}

#[derive(Serialize)]
pub struct RecentScan {
    pub id: String,
    pub project_name: String,
    pub status: String,
    pub score: Option<i32>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

async fn get_dashboard(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiResponse<DashboardResponse>>, ApiError> {
    if !auth.is_authenticated {
        return Err(ApiError::Auth(crate::auth::AuthError::PermissionDenied));
    }

    let org_id: Uuid = auth.org_id.unwrap_or_default();

    let total_projects: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM projects WHERE organization_id = $1 AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let total_scans: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM scan_jobs sj JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let total_findings: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM findings f JOIN scan_results sr ON f.scan_result_id = sr.id JOIN scan_jobs sj ON sr.scan_job_id = sj.id JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1 AND f.is_suppressed = false",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let critical_findings: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM findings f JOIN scan_results sr ON f.scan_result_id = sr.id JOIN scan_jobs sj ON sr.scan_job_id = sj.id JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1 AND f.severity = 'Critical' AND f.is_suppressed = false",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let high_findings: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM findings f JOIN scan_results sr ON f.scan_result_id = sr.id JOIN scan_jobs sj ON sr.scan_job_id = sj.id JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1 AND f.severity = 'High' AND f.is_suppressed = false",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let medium_findings: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM findings f JOIN scan_results sr ON f.scan_result_id = sr.id JOIN scan_jobs sj ON sr.scan_job_id = sj.id JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1 AND f.severity = 'Medium' AND f.is_suppressed = false",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    let average_score: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT COALESCE(AVG(sr.score), 0.0) FROM scan_results sr JOIN scan_jobs sj ON sr.scan_job_id = sj.id JOIN projects p ON sj.project_id = p.id WHERE p.organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0.0);

    #[derive(sqlx::FromRow)]
    struct RecentScanRow {
        id: Uuid,
        project_name: String,
        status: String,
        score: Option<i32>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let recent_rows: Vec<RecentScanRow> = sqlx::query_as(
        "SELECT sj.id, p.name as project_name, sj.status, sr.score, sj.created_at \
         FROM scan_jobs sj \
         JOIN projects p ON sj.project_id = p.id \
         LEFT JOIN scan_results sr ON sr.scan_job_id = sj.id \
         WHERE p.organization_id = $1 \
         ORDER BY sj.created_at DESC LIMIT 10",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let recent_scans: Vec<RecentScan> = recent_rows
        .into_iter()
        .map(|r| RecentScan {
            id: r.id.to_string(),
            project_name: r.project_name,
            status: r.status,
            score: r.score,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    let severity_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT f.severity, COUNT(*)::bigint as count \
         FROM findings f \
         JOIN scan_results sr ON f.scan_result_id = sr.id \
         JOIN scan_jobs sj ON sr.scan_job_id = sj.id \
         JOIN projects p ON sj.project_id = p.id \
         WHERE p.organization_id = $1 AND f.is_suppressed = false \
         GROUP BY f.severity ORDER BY f.severity",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let findings_by_severity: Vec<SeverityCount> = severity_rows
        .into_iter()
        .map(|(severity, count)| SeverityCount { severity, count })
        .collect();

    Ok(ApiResponse::ok(DashboardResponse {
        total_projects,
        total_scans,
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        average_score,
        recent_scans,
        findings_by_severity,
    }))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v1/dashboard", get(get_dashboard))
}
