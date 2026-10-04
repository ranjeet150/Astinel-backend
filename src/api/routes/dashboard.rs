use crate::api::errors::ApiError;
use crate::api::response::ApiResponse;
use crate::auth::AuthContext;
use crate::core::Severity;
use crate::state::AppState;
use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub const DASHBOARD_CACHE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentScan {
    pub id: String,
    pub project_name: String,
    pub status: String,
    pub score: Option<i32>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

/// Aggregates findings and severity counts from grouped database rows without
/// requiring separate repetitive SQL round trips with hardcoded string filters.
pub fn calculate_severity_metrics(
    severity_rows: &[(String, i64)],
) -> (i64, i64, i64, i64, Vec<SeverityCount>) {
    let mut total_findings: i64 = 0;
    let mut critical_findings: i64 = 0;
    let mut high_findings: i64 = 0;
    let mut medium_findings: i64 = 0;
    let mut findings_by_severity = Vec::with_capacity(severity_rows.len());

    let crit_str = Severity::Critical.as_str();
    let high_str = Severity::High.as_str();
    let med_str = Severity::Medium.as_str();

    for (severity, count) in severity_rows {
        total_findings += count;
        let s_lower = severity.to_lowercase();
        if s_lower == crit_str {
            critical_findings += count;
        } else if s_lower == high_str {
            high_findings += count;
        } else if s_lower == med_str {
            medium_findings += count;
        }
        findings_by_severity.push(SeverityCount {
            severity: severity.clone(),
            count: *count,
        });
    }

    (
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        findings_by_severity,
    )
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
    let mut con = state.redis.con.clone();

    // Check Redis cache first to avoid database load
    if let Ok(Some(cached_json)) = redis::cmd("GET")
        .arg(&cache_key)
        .query_async::<Option<String>>(&mut con)
        .await
    {
        if let Ok(cached_resp) = serde_json::from_str::<DashboardResponse>(&cached_json) {
            return Ok(ApiResponse::ok(cached_resp));
        }
    }

    let total_projects: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM projects WHERE organization_id = $1 AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .unwrap_or(0);

    // Consolidated scan metrics query (total scans and average score in a single query)
    #[derive(sqlx::FromRow)]
    struct ScanStats {
        total_scans: Option<i64>,
        average_score: Option<f64>,
    }

    let scan_stats: ScanStats = sqlx::query_as(
        "SELECT \
            COUNT(DISTINCT sj.id)::bigint as total_scans, \
            COALESCE(AVG(sr.score), 0.0) as average_score \
         FROM scan_jobs sj \
         JOIN projects p ON sj.project_id = p.id \
         LEFT JOIN scan_results sr ON sr.scan_job_id = sj.id \
         WHERE p.organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let total_scans = scan_stats.total_scans.unwrap_or(0);
    let average_score = scan_stats.average_score.unwrap_or(0.0);

    // Consolidated findings query grouped by severity: eliminates 4 repetitive queries
    // with hardcoded strings ('Critical', 'High', 'Medium')
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

    let (
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        findings_by_severity,
    ) = calculate_severity_metrics(&severity_rows);

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
        total_scans,
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        average_score,
        recent_scans,
        findings_by_severity,
    };

    // Cache dashboard result in Redis with TTL
    if let Ok(serialized) = serde_json::to_string(&response) {
        let _: Result<(), _> = redis::cmd("SETEX")
            .arg(&cache_key)
            .arg(DASHBOARD_CACHE_TTL_SECS)
            .arg(&serialized)
            .query_async(&mut con)
            .await;
    }

    Ok(ApiResponse::ok(response))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v1/dashboard", get(get_dashboard))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_severity_metrics() {
        let rows = vec![
            ("Critical".to_string(), 3),
            ("High".to_string(), 5),
            ("Medium".to_string(), 12),
            ("Low".to_string(), 20),
            ("Info".to_string(), 8),
        ];

        let (total, crit, high, med, by_sev) = calculate_severity_metrics(&rows);

        assert_eq!(total, 48);
        assert_eq!(crit, 3);
        assert_eq!(high, 5);
        assert_eq!(med, 12);
        assert_eq!(by_sev.len(), 5);
        assert_eq!(by_sev[0].severity, "Critical");
        assert_eq!(by_sev[0].count, 3);
    }

    #[test]
    fn test_calculate_severity_metrics_empty() {
        let rows = vec![];
        let (total, crit, high, med, by_sev) = calculate_severity_metrics(&rows);

        assert_eq!(total, 0);
        assert_eq!(crit, 0);
        assert_eq!(high, 0);
        assert_eq!(med, 0);
        assert!(by_sev.is_empty());
    }

    #[test]
    fn test_dashboard_response_serde() {
        let response = DashboardResponse {
            total_projects: 2,
            total_scans: 10,
            total_findings: 5,
            critical_findings: 1,
            high_findings: 2,
            medium_findings: 2,
            average_score: 85.5,
            recent_scans: vec![RecentScan {
                id: "test-id".to_string(),
                project_name: "test-proj".to_string(),
                status: "completed".to_string(),
                score: Some(85),
                created_at: "2026-10-04T00:00:00Z".to_string(),
            }],
            findings_by_severity: vec![
                SeverityCount {
                    severity: "Critical".to_string(),
                    count: 1,
                },
            ],
        };

        let json = serde_json::to_string(&response).expect("serialization failed");
        let deserialized: DashboardResponse =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(response, deserialized);
    }
}
