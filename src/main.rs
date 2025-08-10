#![allow(clippy::uninlined_format_args)]
use anyhow::{Context, Result};
use clap::Parser;
use git2::{Repository, Signature};
use octocrab::Octocrab;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::{FromRow, Row};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokei::LanguageType;
use std::collections::HashMap;
use chrono::{NaiveDate, Datelike};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Token for reading repositories (needs repo:read or public_repo scope)
    #[arg(long)]
    read_token: Option<String>,

    /// Token for writing to the README repository (needs repo scope for that specific repo)
    #[arg(long)]
    write_token: Option<String>,

    #[arg(short, long)]
    username: Option<String>,

    #[arg(short, long)]
    repo_name: Option<String>,

    #[arg(long, default_value = "README.md")]
    readme_path: String,

    /// Path to SQLite database for storing commit data
    #[arg(long, default_value = "sqlite:github_stats.db")]
    db_url: String,

    /// Force full rescan of all repositories
    #[arg(long)]
    force_rescan: bool,

    /// Set log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,
    
    /// Additional user emails to match (comma-separated)
    #[arg(long)]
    user_emails: Option<String>,
    
    /// Only process specific repository (e.g. "my-repo")
    #[arg(long)]
    only_repo: Option<String>,
    
    /// Manage blacklist: add commit hashes to exclude (comma-separated)
    #[arg(long)]
    blacklist_add: Option<String>,
    
    /// Manage blacklist: remove commit hashes from blacklist (comma-separated)
    #[arg(long)]
    blacklist_remove: Option<String>,
    
    /// Show current blacklist
    #[arg(long)]
    blacklist_show: bool,
    
    /// Path to JSON file containing blacklisted commits
    #[arg(long, default_value = "blacklist.json")]
    blacklist_file: String,
    
    /// Only recreate output from existing database data without fetching from GitHub
    #[arg(long)]
    recreate_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlacklistEntry {
    commit_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date_added: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlacklistConfig {
    blacklist: Vec<BlacklistEntry>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct CommitStats {
    commit_hash: String,
    repo_full_name: String,
    author_email: String,
    commit_date: i64,
    lines_added: i64,
    lines_removed: i64,
    files_changed: i64,
}

#[derive(Debug, Clone)]
struct FileLanguageStats {
    language: LanguageType,
    lines_added: i64,
    lines_removed: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanguageStats {
    language: String,
    lines_added: i64,
    lines_removed: i64,
    net_lines: i64,
    commits: i64,
}

#[derive(Debug)]
struct DailyLanguageActivity {
    date: NaiveDate,
    language: String,
    lines_added: i64,
    lines_removed: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if it exists
    match dotenv::dotenv() {
        Ok(path) => tracing::debug!("Loaded environment from: {:?}", path),
        Err(e) => tracing::debug!("No .env file loaded: {}", e),
    }
    let mut args = Args::parse();
    
    // Also check environment for user emails if not provided via CLI
    if args.user_emails.is_none() {
        args.user_emails = std::env::var("USER_EMAILS").ok();
    }

    // Initialize tracing subscriber with env filter
    // Can be controlled via RUST_LOG env var or --log-level CLI arg
    let filter = match args.log_level {
        Some(ref level) => tracing_subscriber::EnvFilter::new(level),
        None => tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("github_stats_updater=info".parse()?),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();

    tracing::info!("Starting GitHub Stats Updater");
    tracing::debug!(?args, "Parsed command line arguments");

    // Read token is only required if not recreate_only mode
    let read_token = if !args.recreate_only {
        args.read_token.clone().or_else(|| {
            tracing::debug!("Read token not provided via CLI, checking environment");
            std::env::var("PAT_READ").ok()
        }).ok_or_else(|| {
            anyhow::anyhow!("PAT_READ must be set in environment (.env file or environment variable) or provided as --read-token")
        })?
    } else {
        String::new()  // Empty token when only recreating output
    };

    // Write token is only required if repo_name is provided and we're actually updating
    let write_token = if args.repo_name.is_some() {
        args.write_token.clone().or_else(|| {
            tracing::debug!("Write token not provided via CLI, checking environment");
            std::env::var("PAT_WRITE").ok()
        }).ok_or_else(|| {
            anyhow::anyhow!("PAT_WRITE must be set in environment (.env file or environment variable) or provided as --write-token when --repo-name is specified")
        })?
    } else {
        String::new()  // Empty token when not pushing to README
    };

    // Only initialize GitHub API client if not in recreate_only mode
    let octocrab = if !args.recreate_only {
        tracing::info!("Initializing GitHub API client");
        Some(Octocrab::builder()
            .personal_token(read_token.clone())
            .build()?)
    } else {
        None
    };

    // Initialize database connection pool
    tracing::info!(db_url = %args.db_url, "Initializing database connection");
    let pool = initialize_database(&args.db_url).await?;
    
    // Sync blacklist from JSON file if it exists
    sync_blacklist_from_file(&pool, &args.blacklist_file).await?;
    
    // Handle blacklist management commands
    if args.blacklist_show || args.blacklist_add.is_some() || args.blacklist_remove.is_some() {
        return manage_blacklist(&pool, &args).await;
    }
    
    // Username is required for normal operation
    let username = args.username.clone()
        .ok_or_else(|| anyhow::anyhow!("--username is required for processing commits"))?;
    let repo_name = args.repo_name.clone();  // Optional - if not provided, won't push to README

    // Skip repository fetching if recreate_only is set
    if !args.recreate_only {
        tracing::info!(username = %username, "Fetching repositories");

        let mut page: u8 = 1;
        let mut all_repos = Vec::new();

        loop {
            let repos = octocrab
                .as_ref()
                .unwrap()
                .current()
                .list_repos_for_authenticated_user()
                .per_page(100)
                .page(page)
                .send()
                .await?;

            if repos.items.is_empty() {
                break;
            }

            all_repos.extend(repos.items);
            page += 1;
        }

        tracing::info!(count = all_repos.len(), "Found repositories");

        let temp_dir = TempDir::new()?;

        for repo in all_repos {
            // Process both owned repos and forks
            if let Some(clone_url) = repo.clone_url {
                let repo_full_name = format!("{}/{}", repo.owner.as_ref().unwrap().login, repo.name);
                
                // Skip if filtering for specific repo
                if let Some(ref only) = args.only_repo {
                    if !repo.name.eq_ignore_ascii_case(only) && !repo_full_name.ends_with(&format!("/{}", only)) {
                        continue;
                    }
                }

                // Get the last processed commit for incremental updates
                // But we still enter the repo to check for new commits
                let last_processed = if args.force_rescan {
                    None
                } else {
                    get_last_processed_commit(&pool, &repo_full_name).await?
                };

                tracing::info!(repo = %repo_full_name, "Processing repository");

                let repo_path = temp_dir.path().join(&repo.name);

                // Clone the repository
                let local_repo =
                    match clone_repository(clone_url.as_str(), &repo_path, &read_token) {
                        Ok(repo) => repo,
                        Err(e) => {
                            tracing::error!(repo = %repo_full_name, error = %e, "Failed to clone repository");
                            continue;
                        }
                    };

                // Process commits by the user
                match process_user_commits(
                    &pool,
                    &local_repo,
                    &repo_full_name,
                    &username,
                    args.user_emails.as_deref(),
                    last_processed.as_deref(),
                )
                .await
                {
                    Ok(_) => {},
                    Err(e) => {
                        // Check if this is just an empty repo
                        if e.to_string().contains("reference") && e.to_string().contains("not found") {
                            tracing::info!(repo = %repo_full_name, "Repository appears to be empty (no commits on default branch)");
                        } else {
                            tracing::error!(repo = %repo_full_name, error = %e, "Failed to process commits");
                        }
                        continue;
                    }
                }
            }
        }
    } else {
        tracing::info!("Skipping repository fetching, using existing database data");
    }

    // Generate statistics from database
    let stats = generate_language_stats(&pool, &username).await?;
    
    // Generate daily activity for graph
    let daily_activity = generate_daily_language_activity(&pool, &username).await?;

    // Generate formatted output
    let output = generate_stats_output(&stats, &daily_activity)?;
    
    // Update README with stats and graph (only if repo_name is provided)
    if let Some(repo_name) = repo_name {
        update_readme(&username, &repo_name, &args.readme_path, &stats, &daily_activity, &write_token)?;
        tracing::info!("README updated successfully!");
    } else {
        tracing::info!("No repo-name provided, displaying statistics to console");
        // Output full stats to console
        println!("\n{}", output);
        println!("\n📁 Stats saved to database: {}", args.db_url);
        println!("💡 To push these stats to a GitHub README, provide --repo-name");
    }

    tracing::info!("GitHub Stats Updater completed successfully");

    Ok(())
}

#[tracing::instrument]
async fn initialize_database(db_url: &str) -> Result<SqlitePool> {
    // Create connection pool
    tracing::debug!("Creating SQLite connection pool");
    
    // Ensure the database URL includes the create flag
    let db_url = if db_url.contains('?') {
        format!("{}&mode=rwc", db_url)
    } else {
        format!("{}?mode=rwc", db_url)
    };
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .context("Failed to connect to database")?;

    tracing::info!("Database connected, creating tables if needed");
    // Create tables
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commits (
            commit_hash TEXT PRIMARY KEY,
            repo_full_name TEXT NOT NULL,
            author_email TEXT NOT NULL,
            commit_date INTEGER NOT NULL,
            lines_added INTEGER NOT NULL,
            lines_removed INTEGER NOT NULL,
            files_changed INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commit_languages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            commit_hash TEXT NOT NULL,
            language TEXT NOT NULL,
            lines_added INTEGER NOT NULL,
            lines_removed INTEGER NOT NULL,
            FOREIGN KEY (commit_hash) REFERENCES commits(commit_hash),
            UNIQUE(commit_hash, language)
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS last_processed (
            repo_full_name TEXT PRIMARY KEY,
            last_commit_hash TEXT NOT NULL,
            last_checked INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_commits_author ON commits(author_email)")
        .execute(&pool)
        .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_commit_languages_hash ON commit_languages(commit_hash)",
    )
    .execute(&pool)
    .await?;

    // Create blacklist table for excluded commits
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commit_blacklist (
            commit_hash TEXT PRIMARY KEY,
            reason TEXT,
            added_date INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

#[tracing::instrument(skip(token))]
fn clone_repository(clone_url: &str, repo_path: &Path, token: &str) -> Result<Repository> {
    tracing::debug!("Attempting to clone repository from {}", clone_url);
    
    // First try with token authentication
    let https_url = clone_url.replace("git@github.com:", "https://github.com/");
    let auth_url = https_url.replace("https://", &format!("https://{}@", token));
    
    match Repository::clone(&auth_url, repo_path) {
        Ok(repo) => {
            tracing::debug!("Repository cloned successfully with auth");
            Ok(repo)
        }
        Err(e) => {
            tracing::debug!(error = %e, "Clone with auth failed, trying without");
            // Try without authentication (for public repos)
            Repository::clone(clone_url, repo_path)
                .or_else(|_| Repository::clone(&https_url, repo_path))
                .with_context(|| format!("Failed to clone repository from {}", clone_url))
        }
    }
}

#[tracing::instrument(skip(pool, repo))]
async fn process_user_commits(
    pool: &SqlitePool,
    repo: &Repository,
    repo_full_name: &str,
    username: &str,
    additional_emails: Option<&str>,
    last_processed: Option<&str>,
) -> Result<()> {
    tracing::info!(repo = %repo_full_name, "Starting commit processing for repository");
    
    // Check if the repository has any commits
    let head = match repo.head() {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("Repository appears to be empty or have no HEAD: {}", e);
            return Ok(()); // Empty repository, nothing to process
        }
    };
    
    // Make sure HEAD points to a commit
    let head_commit = match head.peel_to_commit() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("HEAD doesn't point to a valid commit: {}", e);
            return Ok(()); // No valid commits
        }
    };
    
    let head_oid = head_commit.id();
    tracing::debug!("HEAD commit: {}", head_oid);
    
    let mut revwalk = repo.revwalk()?;
    // Walk all branches, not just HEAD
    revwalk.push_glob("refs/heads/*")?;
    revwalk.push_glob("refs/remotes/origin/*")?;

    // Pre-populate user's email addresses - don't learn them dynamically
    let mut user_emails = std::collections::HashSet::new();
    user_emails.insert(format!("{}@users.noreply.github.com", username));
    user_emails.insert(format!("{}@users.noreply.github.com", username.to_lowercase()));
    
    // Add additional emails from config/environment
    if let Some(emails) = additional_emails {
        for email in emails.split(',') {
            let email = email.trim().to_lowercase();
            if !email.is_empty() {
                user_emails.insert(email);
            }
        }
    }
    
    tracing::info!("Configured user email patterns: {:?}", user_emails);

    let mut last_commit_hash = String::new();
    let mut processed_count = 0;
    let mut skipped_count = 0;
    let mut total_commits_seen = 0;
    let mut total_lines_added = 0i64;
    let mut total_lines_removed = 0i64;
    let mut processed_hashes = std::collections::HashSet::new();

    for oid_result in revwalk {
        let oid = oid_result?;
        
        // Skip if we've already processed this commit (can happen with multiple branches)
        if !processed_hashes.insert(oid) {
            continue;
        }
        
        let commit = repo.find_commit(oid)?;
        let commit_hash = oid.to_string();
        total_commits_seen += 1;

        // Check if we've seen this commit before (for incremental updates)
        if let Some(last) = last_processed {
            if commit_hash == last {
                tracing::info!("Reached previously processed commit {} after {} new commits", &commit_hash[..8], processed_count);
                break;  // Stop here, we've seen everything after this
            }
        }
        
        // Note: We don't skip blacklisted commits during processing
        // They are filtered out during stats generation only

        // Track the first commit we process (will be the latest)
        if last_commit_hash.is_empty() {
            last_commit_hash = commit_hash.clone();
        }

        let author = commit.author();
        let author_email = author.email().unwrap_or("").to_lowercase();
        let author_name = author.name().unwrap_or("");

        // Check if this commit is by our user (strict matching, no learning)
        let is_user_commit = user_emails.contains(&author_email) ||
            author_name.eq_ignore_ascii_case(username) ||
            author_email.contains(&username.to_lowercase());
        
        if !is_user_commit {
            skipped_count += 1;
            if skipped_count <= 10 {
                tracing::debug!(
                    "Skipping commit {} from {} ({})",
                    &commit_hash[..8],
                    author_name,
                    author_email
                );
            }
            continue;
        }
        
        tracing::trace!(
            commit = %commit_hash,
            author_email = %author_email,
            author_name = %author_name,
            "Processing user commit"
        );

        // Note: We now handle merge commits in get_commit_stats_with_languages
        // They will be diffed against their first parent
        
        // Get commit diff stats with language breakdown
        let (stats, language_stats) = match get_commit_stats_with_languages(repo, &commit) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(commit = %commit_hash, error = %e, "Failed to get commit stats, skipping");
                continue;
            }
        };
        
        let (lines_added, lines_removed, files_changed) = stats;
        total_lines_added += lines_added;
        total_lines_removed += lines_removed;
        
        if lines_added > 0 || lines_removed > 0 {
            tracing::debug!(
                "Commit {}: +{} -{} lines in {} files",
                &commit_hash[..8],
                lines_added,
                lines_removed,
                files_changed
            );
        }

        // Store commit in database with language statistics
        store_commit_with_languages(
            pool,
            &commit_hash,
            repo_full_name,
            &author_email,
            &commit,
            stats,
            language_stats,
        )
        .await?;

        processed_count += 1;

        if processed_count % 100 == 0 {
            tracing::info!(repo = %repo_full_name, count = processed_count, "Processing commits");
        }
    }

    // Update last processed commit for incremental updates
    if !last_commit_hash.is_empty() && processed_count > 0 {
        update_last_processed(pool, repo_full_name, &last_commit_hash).await?;
    }

    tracing::info!(
        repo = %repo_full_name,
        commits_processed = processed_count,
        commits_skipped = skipped_count,
        total_commits_seen = total_commits_seen,
        total_lines_added = total_lines_added,
        total_lines_removed = total_lines_removed,
        net_lines = total_lines_added - total_lines_removed,
        "Finished processing repository"
    );

    Ok(())
}

#[tracing::instrument(skip(repo, commit))]
fn get_commit_stats_with_languages(repo: &Repository, commit: &git2::Commit) -> Result<((i64, i64, i64), Vec<FileLanguageStats>)> {
    // Get the tree for this commit
    let tree = commit.tree()?;

    // Get parent tree
    let parent_tree = if commit.parent_count() == 0 {
        tracing::debug!("Initial commit (no parent): {}", commit.id());
        None
    } else {
        // For commits with parents (including merge commits), diff against first parent
        // This shows what changes were introduced by this commit/merge
        if commit.parent_count() > 1 {
            tracing::debug!("Merge commit {} with {} parents, diffing against first parent", commit.id(), commit.parent_count());
        }
        Some(commit.parent(0)?.tree()?)
    };

    // Calculate diff with options to handle large diffs
    let mut diff_opts = git2::DiffOptions::new();
    diff_opts.context_lines(0);  // We don't need context
    diff_opts.interhunk_lines(0);
    
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

    let stats = diff.stats()?;
    let total_lines_added = stats.insertions() as i64;
    let total_lines_removed = stats.deletions() as i64;
    let files_changed = stats.files_changed() as i64;
    
    if commit.parent_count() == 0 {
        tracing::info!(
            "Initial commit stats: {} files, +{} lines",
            files_changed,
            total_lines_added
        );
    }

    // Track language-specific changes
    let mut language_map: HashMap<LanguageType, FileLanguageStats> = HashMap::new();
    
    // Iterate through each file in the diff
    let num_deltas = diff.deltas().len();
    for idx in 0..num_deltas {
        let delta = diff.get_delta(idx).ok_or_else(|| anyhow::anyhow!("Failed to get delta at index {}", idx))?;
        
        // Get the file path (use new file if available, otherwise old file for deletions)
        let file_path = delta.new_file().path()
            .or_else(|| delta.old_file().path());
            
        if let Some(path) = file_path {
            // Determine language from file extension
            let path_str = path.to_string_lossy();
            let language = match path_str.rsplit('.').next() {
                Some("rs") => LanguageType::Rust,
                Some("py") => LanguageType::Python,
                Some("js") | Some("jsx") => LanguageType::JavaScript,
                Some("ts") | Some("tsx") => LanguageType::TypeScript,
                Some("go") => LanguageType::Go,
                Some("java") => LanguageType::Java,
                Some("c") => LanguageType::C,
                Some("cpp") | Some("cc") | Some("cxx") => LanguageType::Cpp,
                Some("h") | Some("hpp") => LanguageType::CHeader,
                Some("cs") => LanguageType::CSharp,
                Some("rb") => LanguageType::Ruby,
                Some("php") => LanguageType::Php,
                Some("swift") => LanguageType::Swift,
                Some("kt") | Some("kts") => LanguageType::Kotlin,
                Some("scala") => LanguageType::Scala,
                Some("sh") | Some("bash") => LanguageType::Bash,
                Some("sql") => LanguageType::Sql,
                Some("html") | Some("htm") => LanguageType::Html,
                Some("css") | Some("scss") | Some("sass") => LanguageType::Css,
                Some("json") => LanguageType::Json,
                Some("xml") => LanguageType::Xml,
                Some("yaml") | Some("yml") => LanguageType::Yaml,
                Some("toml") => LanguageType::Toml,
                Some("md") | Some("markdown") => LanguageType::Markdown,
                Some("r") => LanguageType::R,
                Some("lua") => LanguageType::Lua,
                Some("vim") => LanguageType::VimScript,
                Some("dart") => LanguageType::Dart,
                Some("ex") | Some("exs") => LanguageType::Elixir,
                Some("erl") | Some("hrl") => LanguageType::Erlang,
                Some("hs") => LanguageType::Haskell,
                Some("jl") => LanguageType::Julia,
                Some("ml") | Some("mli") => LanguageType::OCaml,
                Some("pl") | Some("pm") => LanguageType::Perl,
                Some("vue") => LanguageType::Vue,
                Some("svelte") => LanguageType::Svelte,
                Some("tex") => LanguageType::Tex,
                Some("dockerfile") | Some("Dockerfile") => LanguageType::Dockerfile,
                _ => LanguageType::Text,
            };
            
            // Get file-specific diff stats using patch
            if let Ok(Some(patch)) = git2::Patch::from_diff(&diff, idx) {
                let (_, additions, deletions) = patch.line_stats()?;
                
                if additions > 0 || deletions > 0 {
                    let entry = language_map.entry(language).or_insert_with(|| FileLanguageStats {
                        language: language.clone(),
                        lines_added: 0,
                        lines_removed: 0,
                    });
                    
                    entry.lines_added += additions as i64;
                    entry.lines_removed += deletions as i64;
                    
                    tracing::trace!(
                        "  File {:?}: +{} -{} lines ({})",
                        path_str,
                        additions,
                        deletions,
                        format!("{:?}", language)
                    );
                }
            }
        }
    }

    let language_stats: Vec<FileLanguageStats> = language_map.into_values().collect();

    Ok(((total_lines_added, total_lines_removed, files_changed), language_stats))
}

#[tracing::instrument(skip(pool, commit, language_stats), fields(commit_hash = %commit_hash))]
async fn store_commit_with_languages<'a>(
    pool: &SqlitePool,
    commit_hash: &str,
    repo_full_name: &str,
    author_email: &str,
    commit: &git2::Commit<'a>,
    stats: (i64, i64, i64),
    language_stats: Vec<FileLanguageStats>,
) -> Result<()> {
    let (lines_added, lines_removed, files_changed) = stats;
    let commit_time = commit.time().seconds();

    tracing::debug!(
        commit = %commit_hash,
        lines_added,
        lines_removed,
        files_changed,
        languages = language_stats.len(),
        "Storing commit data with language breakdown"
    );

    // Start a transaction
    let mut tx = pool.begin().await?;

    // Store the main commit data
    sqlx::query(
        "INSERT OR IGNORE INTO commits (commit_hash, repo_full_name, author_email, commit_date, lines_added, lines_removed, files_changed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(commit_hash)
    .bind(repo_full_name)
    .bind(author_email)
    .bind(commit_time)
    .bind(lines_added)
    .bind(lines_removed)
    .bind(files_changed)
    .execute(&mut *tx)
    .await?;

    // Store language-specific statistics
    for lang_stat in language_stats {
        let language_name = format!("{:?}", lang_stat.language);
        
        // Use INSERT OR REPLACE to update existing entries
        sqlx::query(
            "INSERT OR REPLACE INTO commit_languages (commit_hash, language, lines_added, lines_removed)
             VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(commit_hash)
        .bind(&language_name)
        .bind(lang_stat.lines_added)
        .bind(lang_stat.lines_removed)
        .execute(&mut *tx)
        .await?;
    }

    // Commit the transaction
    tx.commit().await?;

    Ok(())
}

async fn get_last_processed_commit(
    pool: &SqlitePool,
    repo_full_name: &str,
) -> Result<Option<String>> {
    let result =
        sqlx::query("SELECT last_commit_hash FROM last_processed WHERE repo_full_name = ?1")
            .bind(repo_full_name)
            .fetch_optional(pool)
            .await?;

    Ok(result.map(|row| row.get::<String, _>("last_commit_hash")))
}

async fn update_last_processed(
    pool: &SqlitePool,
    repo_full_name: &str,
    commit_hash: &str,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT OR REPLACE INTO last_processed (repo_full_name, last_commit_hash, last_checked)
         VALUES (?1, ?2, ?3)",
    )
    .bind(repo_full_name)
    .bind(commit_hash)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

#[tracing::instrument(skip(pool))]
async fn generate_language_stats(pool: &SqlitePool, username: &str) -> Result<Vec<LanguageStats>> {
    tracing::info!("Generating language statistics");

    // Get all email addresses associated with this user
    let user_emails_query = sqlx::query(
        "SELECT DISTINCT author_email FROM commits"
    )
    .fetch_all(pool)
    .await?;
    
    let mut user_emails = Vec::new();
    for row in user_emails_query {
        let email: String = row.get("author_email");
        // Check if this email likely belongs to our user
        if email.contains(username) || email.contains(&username.to_lowercase()) {
            user_emails.push(email);
        }
    }
    
    // Always include the GitHub noreply email
    let github_noreply = format!("{}@users.noreply.github.com", username);
    if !user_emails.contains(&github_noreply) {
        user_emails.push(github_noreply);
    }
    
    tracing::debug!(emails = ?user_emails, "Found user emails for stats");

    // Build a query with multiple email conditions
    let email_conditions = user_emails
        .iter()
        .map(|_| "author_email = ?")
        .collect::<Vec<_>>()
        .join(" OR ");
    
    if email_conditions.is_empty() {
        // No emails found, return empty stats
        return Ok(vec![LanguageStats {
            language: "Total".to_string(),
            lines_added: 0,
            lines_removed: 0,
            net_lines: 0,
            commits: 0,
        }]);
    }

    // First get total stats from commits table (excluding blacklisted)
    let query_str = format!(
        "SELECT 
            COUNT(DISTINCT c.commit_hash) as commits,
            COALESCE(SUM(c.lines_added), 0) as total_added,
            COALESCE(SUM(c.lines_removed), 0) as total_removed,
            COALESCE(SUM(c.lines_added - c.lines_removed), 0) as net_lines
         FROM commits c
         WHERE ({}) 
         AND c.commit_hash NOT IN (SELECT commit_hash FROM commit_blacklist)",
        email_conditions
    );
    
    let mut query = sqlx::query(&query_str);
    for email in &user_emails {
        query = query.bind(email);
    }
    
    let total_row = query.fetch_one(pool).await?;

    let mut stats = vec![LanguageStats {
        language: "Total".to_string(),
        lines_added: total_row.get::<i64, _>("total_added"),
        lines_removed: total_row.get::<i64, _>("total_removed"),
        net_lines: total_row.get::<i64, _>("net_lines"),
        commits: total_row.get::<i64, _>("commits"),
    }];

    // Now get language-specific stats (excluding blacklisted)
    let lang_query_str = format!(
        "SELECT 
            cl.language,
            COUNT(DISTINCT cl.commit_hash) as commits,
            COALESCE(SUM(cl.lines_added), 0) as lines_added,
            COALESCE(SUM(cl.lines_removed), 0) as lines_removed,
            COALESCE(SUM(cl.lines_added - cl.lines_removed), 0) as net_lines
         FROM commit_languages cl
         INNER JOIN commits c ON cl.commit_hash = c.commit_hash
         WHERE ({}) 
         AND c.commit_hash NOT IN (SELECT commit_hash FROM commit_blacklist)
         GROUP BY cl.language
         ORDER BY SUM(cl.lines_added - cl.lines_removed) DESC",
        email_conditions
    );
    
    let mut lang_query = sqlx::query(&lang_query_str);
    for email in &user_emails {
        lang_query = lang_query.bind(email);
    }
    
    let language_rows = lang_query.fetch_all(pool).await?;

    for row in language_rows {
        let language: String = row.get("language");
        
        // Skip non-programming languages
        if matches!(language.as_str(), "Text" | "Json" | "Xml" | "Yaml" | "Toml" | "Markdown" | "Html" | "Css" | "Dockerfile") {
            continue;
        }
        
        stats.push(LanguageStats {
            language,
            lines_added: row.get::<i64, _>("lines_added"),
            lines_removed: row.get::<i64, _>("lines_removed"),
            net_lines: row.get::<i64, _>("net_lines"),
            commits: row.get::<i64, _>("commits"),
        });
    }

    tracing::info!(
        total_commits = stats[0].commits,
        total_lines_added = stats[0].lines_added,
        total_lines_removed = stats[0].lines_removed,
        languages_tracked = stats.len() - 1,
        "Generated language statistics"
    );

    Ok(stats)
}

#[tracing::instrument(skip(pool))]
async fn generate_daily_language_activity(pool: &SqlitePool, username: &str) -> Result<Vec<DailyLanguageActivity>> {
    tracing::info!("Generating daily language activity");
    
    // Get all email addresses associated with this user (same logic as generate_language_stats)
    let user_emails_query = sqlx::query("SELECT DISTINCT author_email FROM commits")
        .fetch_all(pool)
        .await?;
    
    let mut user_emails = Vec::new();
    for row in user_emails_query {
        let email: String = row.get("author_email");
        if email.contains(username) || email.contains(&username.to_lowercase()) {
            user_emails.push(email);
        }
    }
    
    let github_noreply = format!("{}@users.noreply.github.com", username);
    if !user_emails.contains(&github_noreply) {
        user_emails.push(github_noreply);
    }
    
    if user_emails.is_empty() {
        return Ok(Vec::new());
    }
    
    // Build query for daily activity
    let email_conditions = user_emails
        .iter()
        .map(|_| "c.author_email = ?")
        .collect::<Vec<_>>()
        .join(" OR ");
    
    let query_str = format!(
        "SELECT 
            DATE(c.commit_date, 'unixepoch') as day,
            cl.language,
            SUM(cl.lines_added) as lines_added,
            SUM(cl.lines_removed) as lines_removed
         FROM commit_languages cl
         INNER JOIN commits c ON cl.commit_hash = c.commit_hash
         WHERE ({}) 
         AND c.commit_hash NOT IN (SELECT commit_hash FROM commit_blacklist)
         GROUP BY DATE(c.commit_date, 'unixepoch'), cl.language
         ORDER BY day, cl.language",
        email_conditions
    );
    
    let mut query = sqlx::query(&query_str);
    for email in &user_emails {
        query = query.bind(email);
    }
    
    let rows = query.fetch_all(pool).await?;
    
    let mut activity = Vec::new();
    for row in rows {
        let date_str: String = row.get("day");
        let language: String = row.get("language");
        
        // Skip non-programming languages
        if matches!(language.as_str(), "Text" | "Json" | "Xml" | "Yaml" | "Toml" | "Markdown" | "Html" | "Css" | "Dockerfile") {
            continue;
        }
        
        if let Ok(date) = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
            activity.push(DailyLanguageActivity {
                date,
                language,
                lines_added: row.get::<i64, _>("lines_added"),
                lines_removed: row.get::<i64, _>("lines_removed"),
            });
        }
    }
    
    tracing::info!(days = activity.len(), "Generated daily activity data");
    Ok(activity)
}

fn generate_unicode_bar(value: f64, max_value: f64, width: usize) -> String {
    let blocks = [" ", "\u{258f}", "\u{258e}", "\u{258d}", "\u{258c}", "\u{258b}", "\u{258a}", "\u{2589}", "\u{2588}"];
    let ratio = if max_value > 0.0 { value / max_value } else { 0.0 };
    let filled = (ratio * width as f64) as usize;
    let remainder = ((ratio * width as f64 - filled as f64) * 8.0) as usize;
    
    let mut bar = String::new();
    for _ in 0..filled.min(width) {
        bar.push('\u{2588}');
    }
    if filled < width && remainder > 0 {
        bar.push_str(blocks[remainder.min(8)]);
    }
    for _ in (filled + 1)..width {
        bar.push(' ');
    }
    bar
}

fn generate_stats_output(stats: &[LanguageStats], daily_activity: &[DailyLanguageActivity]) -> Result<String> {
    let total_stat = stats
        .iter()
        .find(|s| s.language == "Total")
        .ok_or_else(|| anyhow::anyhow!("No stats found"))?;

    let mut content = String::from("📊 GitHub Contribution Statistics\n");
    content.push_str(&"=".repeat(50));
    content.push_str("\n*Based on actual commits across all repositories (including forks)*\n\n");

    let net_total_str = if total_stat.net_lines >= 0 {
        format_number(total_stat.net_lines as usize)
    } else {
        format!("-{}", format_number((-total_stat.net_lines) as usize))
    };
    
    content.push_str(&format!(
        "📈 Overall Statistics\n{}\n\
        • Total Commits:   {:>12}\n\
        • Lines Added:     {:>12}\n\
        • Lines Removed:   {:>12}\n\
        • Net Lines:       {:>12}\n\n",
        "-".repeat(22),
        format_number(total_stat.commits as usize),
        format_number(total_stat.lines_added as usize),
        format_number(total_stat.lines_removed as usize),
        net_total_str
    ));

    // Add language breakdown if we have language-specific stats
    let language_stats: Vec<&LanguageStats> = stats
        .iter()
        .filter(|s| s.language != "Total")
        .collect();
    
    if !language_stats.is_empty() {
        content.push_str("💻 Language Breakdown\n");
        content.push_str(&"-".repeat(22));
        content.push_str("\n");
        content.push_str(&format!("{:<15} {:>10} {:>12} {:>12} {:>8}\n", 
            "Language", "Net Lines", "Added", "Removed", "Commits"));
        content.push_str(&format!("{:<15} {:>10} {:>12} {:>12} {:>8}\n", 
            "-".repeat(15), "-".repeat(10), "-".repeat(12), "-".repeat(12), "-".repeat(8)));
        
        for lang_stat in language_stats.iter().take(15) {  // Show top 15 languages
            let net_str = if lang_stat.net_lines >= 0 {
                format_number(lang_stat.net_lines as usize)
            } else {
                format!("-{}", format_number((-lang_stat.net_lines) as usize))
            };
            
            content.push_str(&format!(
                "{:<15} {:>10} {:>12} {:>12} {:>8}\n",
                lang_stat.language,
                net_str,
                format_number(lang_stat.lines_added as usize),
                format_number(lang_stat.lines_removed as usize),
                format_number(lang_stat.commits as usize)
            ));
        }
        content.push_str("\n");
    }
    
    // Add activity visualizations
    if !daily_activity.is_empty() {
        content.push_str("📊 Code Activity Visualizations\n");
        content.push_str(&"=".repeat(50));
        content.push_str("\n\n");
        
        // Generate charts
        if let Ok(charts) = generate_activity_charts(daily_activity) {
            content.push_str(&charts);
        }
        
        // Add date range info
        let min_date = daily_activity.iter().map(|a| a.date).min().unwrap();
        let max_date = daily_activity.iter().map(|a| a.date).max().unwrap();
        content.push_str(&format!(
            "*Data from {} to {}*\n",
            min_date.format("%Y-%m-%d"),
            max_date.format("%Y-%m-%d")
        ));
    }

    content.push_str(&format!(
        "\n*Generated: {}*",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));

    Ok(content)
}

fn generate_activity_charts(daily_activity: &[DailyLanguageActivity]) -> Result<String> {
    if daily_activity.is_empty() {
        return Ok(String::new());
    }
    
    let mut output = String::new();
    
    // Group by month for better visualization
    let mut monthly_data: HashMap<String, HashMap<String, (i64, i64)>> = HashMap::new();
    for activity in daily_activity {
        let month_key = activity.date.format("%Y-%m").to_string();
        let entry = monthly_data
            .entry(month_key)
            .or_insert_with(HashMap::new)
            .entry(activity.language.clone())
            .or_insert((0, 0));
        entry.0 += activity.lines_added;
        entry.1 += activity.lines_removed;
    }
    
    // Get language totals for sorting
    let mut language_totals: HashMap<String, i64> = HashMap::new();
    for month_data in monthly_data.values() {
        for (lang, (added, removed)) in month_data {
            *language_totals.entry(lang.clone()).or_insert(0) += added + removed;
        }
    }
    
    let mut top_languages: Vec<_> = language_totals.into_iter().collect();
    top_languages.sort_by_key(|(_, total)| -total);
    let top_langs: Vec<String> = top_languages.iter().take(5).map(|(l, _)| l.clone()).collect();
    
    // Generate monthly activity chart
    output.push_str("#### 📈 Monthly Code Activity (Top 5 Languages)\n\n");
    output.push_str("| Month | Language | Lines Added | Lines Removed | Net Change |\n");
    output.push_str("|-------|----------|-------------|---------------|------------|\n");
    
    let mut sorted_months: Vec<_> = monthly_data.keys().cloned().collect();
    sorted_months.sort();
    
    // Show last 12 months
    for month in sorted_months.iter().rev().take(12).rev() {
        if let Some(month_langs) = monthly_data.get(month) {
            let mut month_languages: Vec<_> = month_langs.iter()
                .filter(|(lang, _)| top_langs.contains(lang))
                .collect();
            month_languages.sort_by_key(|(_, (added, removed))| -(added + removed));
            
            for (lang, (added, removed)) in month_languages.iter().take(3) {
                let net = added - removed;
                let net_str = if net >= 0 {
                    format!("+{}", format_number(net as usize))
                } else {
                    format!("-{}", format_number((-net) as usize))
                };
                
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    month,
                    lang,
                    format_number(*added as usize),
                    format_number(*removed as usize),
                    net_str
                ));
            }
        }
    }
    output.push_str("\n");
    
    // Generate language comparison with bar charts
    output.push_str("#### 📊 Language Activity Comparison\n\n");
    output.push_str("```\n");
    
    let max_value = top_languages.iter().take(10).map(|(_, v)| *v).max().unwrap_or(1) as f64;
    
    for (lang, total) in top_languages.iter().take(10) {
        let bar = generate_unicode_bar(*total as f64, max_value, 30);
        output.push_str(&format!(
            "{:12} {} {:>10}\n",
            lang,
            bar,
            format_number(*total as usize)
        ));
    }
    
    output.push_str("```\n\n");
    
    // Generate weekly trend
    let mut week_map: HashMap<NaiveDate, i64> = HashMap::new();
    
    for activity in daily_activity {
        let week_start = activity.date - chrono::Duration::days(
            activity.date.weekday().num_days_from_monday() as i64
        );
        *week_map.entry(week_start).or_insert(0) += 
            activity.lines_added - activity.lines_removed;
    }
    
    let mut weekly_totals: Vec<(NaiveDate, i64)> = week_map.into_iter().collect();
    weekly_totals.sort_by_key(|(date, _)| *date);
    
    // Show last 20 weeks as sparkline
    output.push_str("#### 📉 Weekly Net Lines Trend (Last 20 Weeks)\n\n");
    output.push_str("```\n");
    
    let recent_weeks: Vec<_> = weekly_totals.iter().rev().take(20).rev().collect();
    if !recent_weeks.is_empty() {
        let max_week = recent_weeks.iter().map(|(_, v)| v.abs()).max().unwrap_or(1) as f64;
        
        for (date, value) in recent_weeks {
            let bar_value = if *value >= 0 {
                generate_unicode_bar(*value as f64, max_week, 40)
            } else {
                format!("{}◄", generate_unicode_bar(value.abs() as f64, max_week, 39))
            };
            
            let value_str = if *value >= 0 {
                format!("+{:>6}", format_number(*value as usize))
            } else {
                format!("-{:>6}", format_number((-value) as usize))
            };
            
            output.push_str(&format!(
                "{} {} {}\n",
                date.format("%Y-%m-%d"),
                bar_value,
                value_str
            ));
        }
    }
    
    output.push_str("```\n\n");
    
    Ok(output)
}

#[tracing::instrument(skip(write_token))]
fn update_readme(username: &str, repo_name: &str, readme_path: &str, stats: &[LanguageStats], daily_activity: &[DailyLanguageActivity], write_token: &str) -> Result<()> {
    tracing::info!("Updating README with latest statistics");
    let total_stat = stats
        .iter()
        .find(|s| s.language == "Total")
        .ok_or_else(|| anyhow::anyhow!("No stats found"))?;

    let mut content = String::from("## 📊 GitHub Contribution Statistics\n\n");
    content.push_str("*Based on actual commits across all repositories (including forks)*\n\n");

    let net_total_str = if total_stat.net_lines >= 0 {
        format_number(total_stat.net_lines as usize)
    } else {
        format!("-{}", format_number((-total_stat.net_lines) as usize))
    };
    
    content.push_str(&format!(
        "### 📈 Overall Statistics\n\n\
        - **Total Commits**: {}\n\
        - **Lines Added**: {:>12}\n\
        - **Lines Removed**: {:>12}\n\
        - **Net Lines**: {:>12}\n\n",
        format_number(total_stat.commits as usize),
        format_number(total_stat.lines_added as usize),
        format_number(total_stat.lines_removed as usize),
        net_total_str
    ));

    // Add language breakdown if we have language-specific stats
    let language_stats: Vec<&LanguageStats> = stats
        .iter()
        .filter(|s| s.language != "Total")
        .collect();
    
    if !language_stats.is_empty() {
        content.push_str("### 💻 Language Breakdown\n\n");
        content.push_str("| Language | Net Lines | Lines Added | Lines Removed | Commits |\n");
        content.push_str("|----------|----------:|------------:|--------------:|--------:|\n");
        
        for lang_stat in language_stats.iter().take(15) {  // Show top 15 languages
            let net_str = if lang_stat.net_lines >= 0 {
                format_number(lang_stat.net_lines as usize)
            } else {
                format!("-{}", format_number((-lang_stat.net_lines) as usize))
            };
            
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                lang_stat.language,
                net_str,
                format_number(lang_stat.lines_added as usize),
                format_number(lang_stat.lines_removed as usize),
                format_number(lang_stat.commits as usize)
            ));
        }
        content.push_str("\n");
    }
    
    // Add activity visualizations
    if !daily_activity.is_empty() {
        content.push_str("### 📊 Code Activity Visualizations\n\n");
        
        // Generate charts
        if let Ok(charts) = generate_activity_charts(daily_activity) {
            content.push_str(&charts);
        }
        
        // Add date range info
        let min_date = daily_activity.iter().map(|a| a.date).min().unwrap();
        let max_date = daily_activity.iter().map(|a| a.date).max().unwrap();
        content.push_str(&format!(
            "*Data from {} to {}*\n\n",
            min_date.format("%Y-%m-%d"),
            max_date.format("%Y-%m-%d")
        ));
    }

    content.push_str(&format!(
        "*Last updated: {}*\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));

    // Clone or use existing README repository
    let repo_path = PathBuf::from(repo_name);
    if !repo_path.exists() {
        tracing::info!("README repository not found locally, cloning");
        Repository::clone(
            &format!(
                "https://{}@github.com/{}/{}.git",
                write_token, username, repo_name
            ),
            &repo_path,
        )?;
    } else {
        tracing::debug!("Using existing README repository");
    }

    let readme_full_path = repo_path.join(readme_path);
    fs::write(&readme_full_path, content)?;

    // Commit and push changes
    let repo = Repository::open(&repo_path)?;
    let mut index = repo.index()?;
    index.add_path(Path::new(readme_path))?;
    index.write()?;

    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let parent_commit = repo.head()?.peel_to_commit()?;
    let signature = Signature::now("GitHub Stats Bot", "bot@example.com")?;

    let commit_id = repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Update code statistics",
        &tree,
        &[&parent_commit],
    )?;
    tracing::info!(commit = %commit_id, "Created commit");

    // Push to remote
    tracing::info!("Pushing changes to remote repository");
    let mut remote = repo.find_remote("origin")?;

    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(|_, _, _| git2::Cred::userpass_plaintext(write_token, ""));

    let mut push_options = git2::PushOptions::new();
    push_options.remote_callbacks(callbacks);

    remote.push(
        &["refs/heads/main:refs/heads/main"],
        Some(&mut push_options),
    )?;
    tracing::info!("Successfully pushed changes to remote");

    Ok(())
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

#[tracing::instrument(skip(pool))]
async fn sync_blacklist_from_file(pool: &SqlitePool, blacklist_file: &str) -> Result<()> {
    let path = Path::new(blacklist_file);
    
    if !path.exists() {
        tracing::debug!("Blacklist file {} does not exist, skipping sync", blacklist_file);
        return Ok(());
    }
    
    tracing::info!("Syncing blacklist from file: {}", blacklist_file);
    
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read blacklist file: {}", blacklist_file))?;
    
    let config: BlacklistConfig = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse blacklist JSON from: {}", blacklist_file))?;
    
    // Get existing blacklist from database
    let existing_rows = sqlx::query("SELECT commit_hash FROM commit_blacklist")
        .fetch_all(pool)
        .await?;
    
    let mut existing_hashes = std::collections::HashSet::new();
    for row in existing_rows {
        let hash: String = row.get("commit_hash");
        existing_hashes.insert(hash);
    }
    
    // Track what's in the JSON file
    let mut json_hashes = std::collections::HashSet::new();
    
    // Add new entries from JSON to database
    let now = chrono::Utc::now().timestamp();
    for entry in &config.blacklist {
        json_hashes.insert(entry.commit_hash.clone());
        
        if !existing_hashes.contains(&entry.commit_hash) {
            let reason = entry.reason.as_deref().unwrap_or("From blacklist.json");
            
            sqlx::query(
                "INSERT INTO commit_blacklist (commit_hash, reason, added_date) VALUES (?1, ?2, ?3)"
            )
            .bind(&entry.commit_hash)
            .bind(reason)
            .bind(now)
            .execute(pool)
            .await?;
            
            tracing::info!("Added {} to blacklist from JSON file", &entry.commit_hash);
        }
    }
    
    // Remove entries from database that are not in JSON file
    for existing_hash in &existing_hashes {
        if !json_hashes.contains(existing_hash) {
            sqlx::query("DELETE FROM commit_blacklist WHERE commit_hash = ?1")
                .bind(existing_hash)
                .execute(pool)
                .await?;
            
            tracing::info!("Removed {} from blacklist (not in JSON file)", existing_hash);
        }
    }
    
    tracing::info!(
        "Blacklist sync complete: {} entries in sync",
        json_hashes.len()
    );
    
    Ok(())
}

#[tracing::instrument(skip(pool))]
async fn manage_blacklist(pool: &SqlitePool, args: &Args) -> Result<()> {
    // Helper function to save current blacklist to JSON file
    async fn save_blacklist_to_file(pool: &SqlitePool, blacklist_file: &str) -> Result<()> {
        let rows = sqlx::query(
            "SELECT commit_hash, reason FROM commit_blacklist ORDER BY added_date DESC"
        )
        .fetch_all(pool)
        .await?;
        
        let mut entries = Vec::new();
        for row in rows {
            let hash: String = row.get("commit_hash");
            let reason: Option<String> = row.get("reason");
            
            entries.push(BlacklistEntry {
                commit_hash: hash,
                reason,
                repository: None,
                date_added: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
            });
        }
        
        let config = BlacklistConfig { blacklist: entries };
        let json = serde_json::to_string_pretty(&config)?;
        fs::write(blacklist_file, json)?;
        
        tracing::info!("Saved blacklist to {}", blacklist_file);
        Ok(())
    }
    
    // Show blacklist
    if args.blacklist_show {
        let rows = sqlx::query(
            "SELECT commit_hash, reason, datetime(added_date, 'unixepoch') as added_at 
             FROM commit_blacklist 
             ORDER BY added_date DESC"
        )
        .fetch_all(pool)
        .await?;
        
        if rows.is_empty() {
            println!("No commits in blacklist.");
        } else {
            println!("\nBlacklisted commits:");
            println!("{:<45} {:<30} {:<20}", "Commit Hash", "Reason", "Added At");
            println!("{}", "-".repeat(95));
            for row in rows {
                let hash: String = row.get("commit_hash");
                let reason: Option<String> = row.get("reason");
                let added_at: String = row.get("added_at");
                println!("{:<45} {:<30} {:<20}", 
                    hash, 
                    reason.unwrap_or_else(|| "No reason provided".to_string()),
                    added_at
                );
            }
        }
    }
    
    // Add to blacklist
    if let Some(hashes) = &args.blacklist_add {
        let hashes: Vec<&str> = hashes.split(',').map(|s| s.trim()).collect();
        for hash in hashes {
            if hash.len() < 7 {
                eprintln!("Warning: Skipping invalid hash '{}' (too short)", hash);
                continue;
            }
            
            let now = chrono::Utc::now().timestamp();
            let result = sqlx::query(
                "INSERT OR IGNORE INTO commit_blacklist (commit_hash, reason, added_date) 
                 VALUES (?1, ?2, ?3)"
            )
            .bind(hash)
            .bind("Manually blacklisted")
            .bind(now)
            .execute(pool)
            .await?;
            
            if result.rows_affected() > 0 {
                println!("Added {} to blacklist", hash);
            } else {
                println!("{} was already in blacklist", hash);
            }
        }
        
        // Save updated blacklist to JSON file
        save_blacklist_to_file(pool, &args.blacklist_file).await?;
    }
    
    // Remove from blacklist
    if let Some(hashes) = &args.blacklist_remove {
        let hashes: Vec<&str> = hashes.split(',').map(|s| s.trim()).collect();
        for hash in hashes {
            let result = sqlx::query("DELETE FROM commit_blacklist WHERE commit_hash = ?1")
                .bind(hash)
                .execute(pool)
                .await?;
                
            if result.rows_affected() > 0 {
                println!("Removed {} from blacklist", hash);
            } else {
                println!("{} was not in blacklist", hash);
            }
        }
        
        // Save updated blacklist to JSON file
        save_blacklist_to_file(pool, &args.blacklist_file).await?;
    }
    
    Ok(())
}

