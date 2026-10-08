use crate::api::errors::ApiError;
use crate::api::response::ApiResponse;
use crate::auth::AuthContext;
use crate::state::AppState;
use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct RecentScan {
    pub id: String,
    pub project_name: String,
    pub status: String,
    pub score: Option<i32>,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(sqlx::FromRow)]
struct ScanStatsRow {
    total_scans: i64,
    average_score: f64,
}

async fn get_dashboard(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiResponse<DashboardResponse>>, ApiError> {
    if !auth.is_authenticated {
        return Err(ApiError::Auth(crate::auth::AuthError::PermissionDenied));
    }

    let org_id: Uuid = auth.org_id.unwrap_or_default();
    let cache_key = format!("dashboard:org:{}", org_id);

    // 1. Try to serve from Redis cache with a 60-second TTL
    let mut con = state.redis.con.clone();
    if let Ok(Some(cached_json)) = redis::cmd("GET")
        .arg(&cache_key)
        .query_async::<_, Option<String>>(&mut con)
        .await
    {
        if let Ok(cached_response) = serde_json::from_str::<DashboardResponse>(&cached_json) {
            return Ok(ApiResponse::ok(cached_response));
        }
    }

    // 2. Query total projects in organization
    let total_projects: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM projects WHERE organization_id = $1 AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    // 3. Consolidated scans & average score in a single query
    let scan_stats: ScanStatsRow = sqlx::query_as(
        "SELECT COUNT(sj.id)::bigint as total_scans, \
                COALESCE(AVG(sr.score), 0.0)::float8 as average_score \
         FROM scan_jobs sj \
         JOIN projects p ON sj.project_id = p.id \
         LEFT JOIN scan_results sr ON sr.scan_job_id = sj.id \
         WHERE p.organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    // 4. Consolidated findings breakdown by severity in a single parameterized round-trip
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

    let mut total_findings: i64 = 0;
    let mut critical_findings: i64 = 0;
    let mut high_findings: i64 = 0;
    let mut medium_findings: i64 = 0;

    let findings_by_severity: Vec<SeverityCount> = severity_rows
        .into_iter()
        .map(|(severity, count)| {
            total_findings += count;
            if severity.eq_ignore_ascii_case("Critical") {
                critical_findings += count;
            } else if severity.eq_ignore_ascii_case("High") {
                high_findings += count;
            } else if severity.eq_ignore_ascii_case("Medium") {
                medium_findings += count;
            }
            SeverityCount { severity, count }
        })
        .collect();

    // 5. Recent scans query (last 10)
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

    let response = DashboardResponse {
        total_projects,
        total_scans: scan_stats.total_scans,
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        average_score: scan_stats.average_score,
        recent_scans,
        findings_by_severity,
    };

    // 6. Cache dashboard response into Redis with a 60-second TTL
    if let Ok(serialized) = serde_json::to_string(&response) {
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg(&cache_key)
            .arg(&serialized)
            .arg("EX")
            .arg(60)
            .query_async(&mut con)
            .await;
    }

    Ok(ApiResponse::ok(response))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v1/dashboard", get(get_dashboard))
}
