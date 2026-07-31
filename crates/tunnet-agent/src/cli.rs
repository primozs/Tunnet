//! Internal enroll/reset used by [`api_bootstrap`] (not exposed as CLI in `tunnetd`).

use anyhow::Context;
use clap::Args;
use tunnet_core::{
    AgentIdentity, ManagedState, PersistedState, SealPolicy, StatePaths, persist_agent,
};

#[derive(Args, Debug)]
pub struct EnrollArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    #[arg(long, env = "TUNNET_ENROLL_TOKEN", conflicts_with = "org")]
    pub token: Option<String>,
    #[arg(long, env = "TUNNET_ORG_SLUG", conflicts_with = "token")]
    pub org: Option<String>,
    #[arg(long, env = "TUNNET_NETWORK")]
    pub network: Option<String>,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long, default_value_t = 600)]
    pub wait_secs: u64,
    #[arg(long, env = "TUNNET_LABELS", conflicts_with = "labels_json")]
    pub labels: Option<String>,
    #[arg(long, env = "TUNNET_LABELS_JSON", conflicts_with = "labels")]
    pub labels_json: Option<String>,
    #[arg(long, env = "TUNNET_EXPIRES_IN")]
    pub expires_in: Option<String>,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct ResetArgs {
    #[arg(long)]
    pub yes: bool,
}

fn paths(cli_state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(cli_state_dir)
}

pub async fn run_enroll(args: EnrollArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;

    let control_loopback = args.control_url.contains("127.0.0.1")
        || args.control_url.contains("localhost")
        || args.control_url.contains("[::1]");
    if control_loopback {
        eprintln!(
            "warning: control URL is loopback ({}).\n\
             This machine can reach the control plane, but other hosts/VMs must enroll with\n\
             the control plane's LAN or public URL, e.g.:\n\
               tunnet enroll --control-url http://<this-host-lan-ip>:8080 --token …\n\
             Otherwise they stay offline on the dashboard and never appear as peers.",
            args.control_url
        );
    }

    if let Ok(existing) = PersistedState::load(&paths) {
        if existing.is_direct() {
            anyhow::bail!(
                "agent is in Direct mode; run `tunnet reset --yes` before enrolling into Managed"
            );
        }
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            existing.primary_network_name().unwrap_or("?")
        );
    }

    let token = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let org = args
        .org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if token.is_none() && org.is_none() {
        anyhow::bail!("provide --token <TOKEN> or --org <slug>");
    }

    let hostname = args
        .hostname
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-node".into());

    let identity = AgentIdentity::generate();
    tracing::info!(endpoint_id = %identity.endpoint_id_hex(), "generated new agent identity");

    let client = tunnet_core::UnauthedClient::new(args.control_url.clone())?;
    let metadata =
        crate::system_info::collect_system_metadata(&hostname, env!("CARGO_PKG_VERSION"));

    let (network_id, network_name) = parse_network_arg(args.network.as_deref())?;

    let labels = match (&args.labels, &args.labels_json) {
        (Some(csv), None) => Some(crate::cmds_device::parse_label_csv(csv)?),
        (None, Some(json)) => Some(crate::cmds_device::parse_labels_json(json)?),
        (None, None) => None,
        _ => unreachable!("clap conflicts_with"),
    };

    let mut resp = client
        .enroll(tunnet_common::EnrollRequest {
            enrollment_token: token,
            organization_slug: org,
            network_id,
            network_name,
            endpoint_id: identity.endpoint_id_hex(),
            hostname: hostname.clone(),
            os: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: Some(metadata),
            labels,
            expires_in: args.expires_in.clone(),
        })
        .await
        .context("enroll with control plane")?;

    if resp.status == "pending" {
        println!(
            "Quick enroll pending approval. endpoint_id={} network={} (waiting up to {}s)",
            identity.endpoint_id_hex(),
            resp.network_name,
            args.wait_secs,
        );
        resp = wait_for_approval(&client, &identity, resp, args.wait_secs).await?;
    }

    let membership = resp
        .snapshot
        .memberships
        .iter()
        .find(|m| m.network_id == resp.network_id)
        .context("enrolled network missing from snapshot")?;

    tracing::info!(
        assigned_ip = %membership.assigned_ipv4,
        network = %resp.network_name,
        peers = membership.ipv4_peers.len(),
        "enrollment successful"
    );

    let persisted = PersistedState::Managed(ManagedState {
        control_url: args.control_url,
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: chrono::Utc::now(),
        hostname: hostname.clone(),
    });
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;
    {
        let mut cfg = tunnet_core::TunnetConfig::ensure(&paths)?;
        cfg.node.hostname = hostname.clone();
        cfg.save(&paths)?;
    }

    println!(
        "Enrolled. endpoint_id={} ip={} network={} (secrets: {})",
        identity.endpoint_id_hex(),
        membership.assigned_ipv4,
        resp.network_name,
        tier.as_str(),
    );
    crate::cmds::finish_after_config(state_dir, false).await?;
    Ok(())
}

fn parse_network_arg(
    network: Option<&str>,
) -> anyhow::Result<(Option<uuid::Uuid>, Option<String>)> {
    let Some(raw) = network.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok((None, None));
    };
    if let Ok(id) = uuid::Uuid::parse_str(raw) {
        return Ok((Some(id), None));
    }
    Ok((None, Some(raw.to_string())))
}

async fn wait_for_approval(
    client: &tunnet_core::UnauthedClient,
    identity: &AgentIdentity,
    pending: tunnet_common::EnrollResponse,
    wait_secs: u64,
) -> anyhow::Result<tunnet_common::EnrollResponse> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for enrollment approval");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let status = client
            .enroll_status(tunnet_common::EnrollStatusRequest {
                endpoint_id: identity.endpoint_id_hex(),
                network_id: pending.network_id,
            })
            .await
            .context("poll enroll status")?;

        match status {
            tunnet_common::EnrollStatusResponse::Pending { .. } => continue,
            tunnet_common::EnrollStatusResponse::Rejected => {
                anyhow::bail!("enrollment was rejected by an organization admin");
            }
            tunnet_common::EnrollStatusResponse::Active {
                organization_id,
                network_id,
                network_name,
                snapshot,
            } => {
                return Ok(tunnet_common::EnrollResponse {
                    organization_id,
                    network_id,
                    network_name,
                    status: "active".into(),
                    snapshot: *snapshot,
                });
            }
        }
    }
}

pub async fn run_reset(args: ResetArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let targets: Vec<std::path::PathBuf> = if state_dir.is_some() {
        vec![paths(state_dir).dir]
    } else {
        vec![tunnet_core::StatePaths::system_dir()]
    };

    if !args.yes {
        eprintln!("Re-run with --yes to wipe:");
        for dir in &targets {
            eprintln!("  {}", dir.display());
        }
        return Ok(());
    }

    let mut wiped_any = false;
    for dir in &targets {
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
            println!("Wiped {}", dir.display());
            wiped_any = true;
        }
    }
    if !wiped_any {
        println!("Nothing to wipe.");
    }
    Ok(())
}
