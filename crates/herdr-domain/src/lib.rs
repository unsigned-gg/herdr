#![forbid(unsafe_code)]
//! Zero-I/O domain types and invariants for `herdr`.
//!
//! Models sessions, panes, agent harnesses, lifecycle states, layout splits,
//! and the estate pane-protection policy ("never type into, restart, or kill
//! another agent's pane or process").
//!
//! This crate is strictly free of I/O (`std::fs`, `std::net`, `std::process`,
//! `tokio`).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Validated session identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Construct a validated [`SessionId`], rejecting empty or whitespace-only names.
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let s = raw.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptySessionId);
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the underlying session identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated pane identifier (e.g. `"%1"`, `"pane-01"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PaneId(String);

impl PaneId {
    /// Construct a validated [`PaneId`], rejecting empty or whitespace-only identifiers.
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let s = raw.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyPaneId);
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the underlying pane identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Supported agent harness or shell kind running inside a pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Claude,
    Agy,
    Omp,
    Codex,
    Shell,
}

impl AgentKind {
    /// Canonical lowercase identifier for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Agy => "agy",
            Self::Omp => "omp",
            Self::Codex => "codex",
            Self::Shell => "shell",
        }
    }

    /// Parse an [`AgentKind`] from its canonical name (case-insensitive).
    #[must_use]
    pub fn from_str_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Self::Claude),
            "agy" | "antigravity" => Some(Self::Agy),
            "omp" | "oh-my-pi" => Some(Self::Omp),
            "codex" => Some(Self::Codex),
            "shell" | "bash" | "zsh" | "sh" => Some(Self::Shell),
            _ => None,
        }
    }

    /// Returns `true` if this pane runs an AI coding agent harness rather than a plain shell.
    #[must_use]
    pub const fn is_agent(self) -> bool {
        !matches!(self, Self::Shell)
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of an agent process inside a pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    Booting,
    IdlePrompt,
    Busy,
    Exited,
}

impl AgentLifecycleState {
    /// Returns `true` when the agent is at its idle prompt and ready to accept input.
    #[must_use]
    pub const fn can_accept_prompt(self) -> bool {
        matches!(self, Self::IdlePrompt)
    }

    /// Returns `true` when a new agent session may be booted into the pane
    /// (requires the previous agent process to have exited).
    #[must_use]
    pub const fn can_boot_agent(self) -> bool {
        matches!(self, Self::Exited)
    }
}

/// Direction of a pane layout split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutSplit {
    Horizontal,
    Vertical,
}

/// Domain validation errors for identifiers and state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainError {
    EmptySessionId,
    EmptyPaneId,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySessionId => f.write_str("session id must not be empty"),
            Self::EmptyPaneId => f.write_str("pane id must not be empty"),
        }
    }
}

impl std::error::Error for DomainError {}

/// Violation of the estate pane-protection invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaneViolation {
    /// Target pane identifier is empty.
    EmptyTargetPane,
    /// Caller attempted to mutate a pane owned by another agent.
    ForeignAgentPane {
        caller_pane: Option<String>,
        target_pane: String,
        target_owner: String,
    },
    /// An agent pane attempted to mutate a different pane.
    CrossPaneMutation {
        caller_pane: String,
        target_pane: String,
    },
}

impl fmt::Display for PaneViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTargetPane => f.write_str("target pane id must not be empty"),
            Self::ForeignAgentPane {
                caller_pane,
                target_pane,
                target_owner,
            } => write!(
                f,
                "pane protection violation: caller {:?} may not mutate pane `{target_pane}` owned by `{target_owner}`",
                caller_pane
            ),
            Self::CrossPaneMutation {
                caller_pane,
                target_pane,
            } => write!(
                f,
                "pane protection violation: caller pane `{caller_pane}` may not mutate foreign pane `{target_pane}`"
            ),
        }
    }
}

impl std::error::Error for PaneViolation {}

/// Enforces the estate rule: never type into, restart, or kill another agent's
/// pane or process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaneProtectionPolicy;

impl PaneProtectionPolicy {
    /// Evaluate whether `caller_pane` is permitted to mutate `target_pane`
    /// (`send-keys`, `prompt`, `restart`, `kill`).
    ///
    /// Rules:
    /// 1. `target_pane` must be non-empty.
    /// 2. If `target_owner` is present, only a caller whose identity matches
    ///    `target_owner` (or is operating on its own `target_pane` when
    ///    `target_owner == target_pane`) is allowed.
    /// 3. If `caller_pane` is `Some(cp)` and `cp != target_pane`, cross-pane
    ///    mutation is rejected unless `target_owner == Some(cp)`.
    pub fn can_mutate_pane(
        caller_pane: Option<&str>,
        target_pane: &str,
        target_owner: Option<&str>,
    ) -> Result<(), PaneViolation> {
        can_mutate_pane(caller_pane, target_pane, target_owner)
    }
}

/// Evaluate whether `caller_pane` is permitted to mutate `target_pane` under
/// the estate pane-protection invariant.
pub fn can_mutate_pane(
    caller_pane: Option<&str>,
    target_pane: &str,
    target_owner: Option<&str>,
) -> Result<(), PaneViolation> {
    let target = target_pane.trim();
    if target.is_empty() {
        return Err(PaneViolation::EmptyTargetPane);
    }

    let caller = caller_pane.map(str::trim).filter(|s| !s.is_empty());
    let owner = target_owner.map(str::trim).filter(|s| !s.is_empty());

    if let Some(owner_id) = owner {
        let caller_matches_owner = caller == Some(owner_id);
        let self_pane_matches_owner = caller == Some(target) && owner_id == target;
        if !caller_matches_owner && !self_pane_matches_owner {
            return Err(PaneViolation::ForeignAgentPane {
                caller_pane: caller.map(str::to_string),
                target_pane: target.to_string(),
                target_owner: owner_id.to_string(),
            });
        }
    }

    if let Some(caller_id) = caller {
        if caller_id != target && owner != Some(caller_id) {
            return Err(PaneViolation::CrossPaneMutation {
                caller_pane: caller_id.to_string(),
                target_pane: target.to_string(),
            });
        }
    }

    Ok(())
}

/// Canonical pane key across named sessions (`<session>/<pane_id>` for non-default
/// sessions, bare `<pane_id>` for `"default"`). Matches `cortex_edge::pane_key`.
#[must_use]
pub fn pane_key(session: &str, pane_id: &str) -> String {
    let sess = session.trim();
    let pane = pane_id.trim();
    if sess.is_empty() || sess == "default" {
        pane.to_string()
    } else {
        format!("{sess}/{pane}")
    }
}

/// Canonical 4-state `agent_status` wire vocabulary for the Ruling S4
/// `herdr agent list` contract (`unsigned-gg/herdr#2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkstationAgentStatus {
    #[default]
    Idle,
    Working,
    Blocked,
    Done,
    #[serde(other)]
    Unknown,
}

/// Canonical `agent_session` object inside an `agent.list` row (Ruling S4 & S6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkstationAgentSession {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub kind: String,
    /// Canonical workstation `session_uuid` join key (`(harness, session_uuid)` per S6).
    pub value: String,
}

/// Minimal frozen S4 contract row emitted in `result.agents[]` by `herdr agent list`
/// and consumed by `cortex_edge::parse_agent_list` and `revenant::sensing::herdr_agents_to_sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkstationAgentRow {
    pub pane_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default)]
    pub agent_status: WorkstationAgentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<WorkstationAgentSession>,
}

/// Inner `result` payload for `herdr agent list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkstationAgentListResult {
    pub agents: Vec<WorkstationAgentRow>,
}

/// Top-level JSON-RPC response envelope for `herdr agent list` (Ruling S4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkstationAgentListEnvelope {
    pub id: String,
    pub result: WorkstationAgentListResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_pane_id_validation() {
        assert_eq!(SessionId::new(" estate ").unwrap().as_str(), "estate");
        assert_eq!(SessionId::new("default").unwrap().to_string(), "default");
        assert_eq!(SessionId::new("   "), Err(DomainError::EmptySessionId));

        assert_eq!(PaneId::new(" %12 ").unwrap().as_str(), "%12");
        assert_eq!(PaneId::new("%12").unwrap().to_string(), "%12");
        assert_eq!(PaneId::new(""), Err(DomainError::EmptyPaneId));
    }

    #[test]
    fn agent_kind_parsing_and_classification() {
        assert_eq!(AgentKind::from_str_name("claude"), Some(AgentKind::Claude));
        assert_eq!(AgentKind::from_str_name("AGY"), Some(AgentKind::Agy));
        assert_eq!(AgentKind::from_str_name("omp"), Some(AgentKind::Omp));
        assert_eq!(AgentKind::from_str_name("codex"), Some(AgentKind::Codex));
        assert_eq!(AgentKind::from_str_name("bash"), Some(AgentKind::Shell));
        assert_eq!(AgentKind::from_str_name("unknown"), None);

        assert!(AgentKind::Claude.is_agent());
        assert!(AgentKind::Agy.is_agent());
        assert!(AgentKind::Omp.is_agent());
        assert!(AgentKind::Codex.is_agent());
        assert!(!AgentKind::Shell.is_agent());
    }

    #[test]
    fn lifecycle_state_transitions() {
        assert!(!AgentLifecycleState::Booting.can_accept_prompt());
        assert!(AgentLifecycleState::IdlePrompt.can_accept_prompt());
        assert!(!AgentLifecycleState::Busy.can_accept_prompt());
        assert!(!AgentLifecycleState::Exited.can_accept_prompt());

        assert!(AgentLifecycleState::Exited.can_boot_agent());
        assert!(!AgentLifecycleState::IdlePrompt.can_boot_agent());
        assert!(!AgentLifecycleState::Busy.can_boot_agent());
    }

    #[test]
    fn pane_protection_allows_self_and_unowned_operator_actions() {
        // Agent mutating its own pane (unowned or self-owned).
        assert_eq!(can_mutate_pane(Some("%1"), "%1", None), Ok(()));
        assert_eq!(can_mutate_pane(Some("%1"), "%1", Some("%1")), Ok(()));
        assert_eq!(
            PaneProtectionPolicy::can_mutate_pane(Some("agent-a"), "%2", Some("agent-a")),
            Ok(())
        );

        // Operator (no caller pane) mutating an unowned shell pane.
        assert_eq!(can_mutate_pane(None, "%3", None), Ok(()));
    }

    #[test]
    fn pane_protection_blocks_foreign_agent_pane_mutation() {
        // Agent in %1 attempting to type into / kill %2 owned by claude-2.
        let res = can_mutate_pane(Some("%1"), "%2", Some("claude-2"));
        assert_eq!(
            res,
            Err(PaneViolation::ForeignAgentPane {
                caller_pane: Some("%1".to_string()),
                target_pane: "%2".to_string(),
                target_owner: "claude-2".to_string(),
            })
        );

        // Agent in %1 attempting to mutate %2 even when %2 has no registered owner.
        let res2 = can_mutate_pane(Some("%1"), "%2", None);
        assert_eq!(
            res2,
            Err(PaneViolation::CrossPaneMutation {
                caller_pane: "%1".to_string(),
                target_pane: "%2".to_string(),
            })
        );

        // Unauthenticated caller attempting to mutate a pane owned by an active agent.
        let res3 = can_mutate_pane(None, "%5", Some("sadr"));
        assert_eq!(
            res3,
            Err(PaneViolation::ForeignAgentPane {
                caller_pane: None,
                target_pane: "%5".to_string(),
                target_owner: "sadr".to_string(),
            })
        );

        // Empty target pane is rejected.
        assert_eq!(
            can_mutate_pane(Some("%1"), "  ", None),
            Err(PaneViolation::EmptyTargetPane)
        );
    }

    #[test]
    fn layout_split_variants() {
        assert_ne!(LayoutSplit::Horizontal, LayoutSplit::Vertical);
    }

    #[test]
    fn s4_workstation_agent_list_contract_roundtrip() {
        assert_eq!(pane_key("default", "w1:p1"), "w1:p1");
        assert_eq!(pane_key("estate", "w4A:p1"), "estate/w4A:p1");

        let raw = r#"{
            "id": "req-1",
            "result": {
                "agents": [
                    {
                        "terminal_id": "t-1",
                        "pane_id": "w4A:p1",
                        "workspace_id": "w4A",
                        "tab_id": "t1",
                        "focused": true,
                        "agent": "agy",
                        "agent_status": "working",
                        "cwd": "/home/ctodie/projects/agents/harness/herdr",
                        "agent_session": {
                            "source": "hook",
                            "agent": "agy",
                            "kind": "id",
                            "value": "02004e7d-5961-4ad0-8e98-451278826314"
                        },
                        "revision": 42
                    }
                ]
            }
        }"#;

        let parsed: WorkstationAgentListEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.id, "req-1");
        assert_eq!(parsed.result.agents.len(), 1);
        let row = &parsed.result.agents[0];
        assert_eq!(row.pane_id, "w4A:p1");
        assert_eq!(row.agent.as_deref(), Some("agy"));
        assert_eq!(row.agent_status, WorkstationAgentStatus::Working);
        assert_eq!(
            row.cwd.as_deref(),
            Some("/home/ctodie/projects/agents/harness/herdr")
        );
        assert_eq!(
            row.agent_session.as_ref().unwrap().value,
            "02004e7d-5961-4ad0-8e98-451278826314"
        );
    }
}
