use anyhow::Result;
use clap::Parser;
use git2::Repository;
use octocrab::Octocrab;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: String,
    
    #[arg(short, long, default_value = "rubenduburck")]
    username: String,
    
    #[arg(short, long, default_value = "rubenduburck")]
    repo_name: String,
    
    #[arg(long, default_value = "README.md")]
    readme_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanguageStats {
    language: String,
    lines: usize,
    files: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    let octocrab = Octocrab::builder()
        .personal_token(args.token.clone())
        .build()?;
    
    println!("Fetching repositories for {}...", args.username);
    
    let mut page = 1u32;
    let mut all_repos = Vec::new();
    
    loop {
        let repos = octocrab
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
    
    println!("Found {} repositories", all_repos.len());
    
    let temp_dir = TempDir::new()?;
    let mut language_totals: HashMap<String, (usize, usize)> = HashMap::new();
    
    for repo in all_repos {
        if repo.fork.unwrap_or(false) {
            println!("Skipping fork: {}", repo.name);
            continue;
        }
        
        if let Some(clone_url) = repo.clone_url {
            println!("Processing: {}", repo.name);
            
            let repo_path = temp_dir.path().join(&repo.name);
            
            let clone_result = Repository::clone(&clone_url.to_string(), &repo_path);
            
            if clone_result.is_err() {
                let https_url = clone_url.to_string().replace("git@github.com:", "https://github.com/");
                let auth_url = https_url.replace("https://", &format!("https://{}@", args.token));
                
                match Repository::clone(&auth_url, &repo_path) {
                    Ok(_) => {},
                    Err(e) => {
                        eprintln!("Failed to clone {}: {}", repo.name, e);
                        continue;
                    }
                }
            }
            
            let stats = count_lines_in_repo(&repo_path)?;
            
            for (lang, (lines, files)) in stats {
                let entry = language_totals.entry(lang).or_insert((0, 0));
                entry.0 += lines;
                entry.1 += files;
            }
        }
    }
    
    let mut stats_vec: Vec<LanguageStats> = language_totals
        .into_iter()
        .map(|(language, (lines, files))| LanguageStats {
            language,
            lines,
            files,
        })
        .collect();
    
    stats_vec.sort_by(|a, b| b.lines.cmp(&a.lines));
    
    update_readme(&args, &stats_vec)?;
    
    println!("README updated successfully!");
    
    Ok(())
}

fn count_lines_in_repo(repo_path: &Path) -> Result<HashMap<String, (usize, usize)>> {
    let mut language_stats: HashMap<String, (usize, usize)> = HashMap::new();
    
    for entry in WalkDir::new(repo_path)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Some(language) = detect_language(entry.path()) {
                let content = fs::read_to_string(entry.path()).unwrap_or_default();
                let line_count = content.lines().count();
                
                let entry = language_stats.entry(language).or_insert((0, 0));
                entry.0 += line_count;
                entry.1 += 1;
            }
        }
    }
    
    Ok(language_stats)
}

fn is_ignored(path: &Path) -> bool {
    path.components().any(|comp| {
        comp.as_os_str() == ".git" ||
        comp.as_os_str() == "node_modules" ||
        comp.as_os_str() == "target" ||
        comp.as_os_str() == "dist" ||
        comp.as_os_str() == "build" ||
        comp.as_os_str() == ".next" ||
        comp.as_os_str() == "vendor" ||
        comp.as_os_str() == "__pycache__" ||
        comp.as_os_str() == ".venv" ||
        comp.as_os_str() == "venv"
    })
}

fn detect_language(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_str()?;
    
    let language = match extension {
        "rs" => "Rust",
        "py" => "Python",
        "js" | "mjs" | "cjs" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "jsx" => "JavaScript/JSX",
        "java" => "Java",
        "c" => "C",
        "cpp" | "cc" | "cxx" => "C++",
        "h" | "hpp" | "hxx" => "C/C++ Header",
        "cs" => "C#",
        "rb" => "Ruby",
        "go" => "Go",
        "php" => "PHP",
        "swift" => "Swift",
        "kt" | "kts" => "Kotlin",
        "scala" => "Scala",
        "sh" | "bash" | "zsh" => "Shell",
        "html" | "htm" => "HTML",
        "css" => "CSS",
        "scss" | "sass" => "SCSS/Sass",
        "sql" => "SQL",
        "r" | "R" => "R",
        "lua" => "Lua",
        "pl" | "pm" => "Perl",
        "dart" => "Dart",
        "vue" => "Vue",
        "svelte" => "Svelte",
        "yaml" | "yml" => "YAML",
        "toml" => "TOML",
        "json" => "JSON",
        "xml" => "XML",
        "md" | "markdown" => "Markdown",
        _ => return None,
    };
    
    Some(language.to_string())
}

fn update_readme(args: &Args, stats: &[LanguageStats]) -> Result<()> {
    let total_lines: usize = stats.iter().map(|s| s.lines).sum();
    let total_files: usize = stats.iter().map(|s| s.files).sum();
    
    let mut content = String::from("## 📊 Lines of Code by Language\n\n");
    content.push_str("*Includes all public and private repositories (excludes forks)*\n\n");
    
    content.push_str("| Language | Lines of Code | Files |\n");
    content.push_str("|----------|--------------|-------|\n");
    
    for stat in stats.iter().take(15) {
        content.push_str(&format!(
            "| {} | {:>12} | {:>6} |\n",
            stat.language,
            format_number(stat.lines),
            format_number(stat.files)
        ));
    }
    
    content.push_str(&format!(
        "| **Total** | **{:>10}** | **{:>4}** |\n\n",
        format_number(total_lines),
        format_number(total_files)
    ));
    
    content.push_str(&format!(
        "*Last updated: {}*\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));
    
    let repo_path = PathBuf::from(&args.repo_name);
    if !repo_path.exists() {
        Repository::clone(
            &format!("https://{}@github.com/{}/{}.git", 
                args.token, args.username, args.repo_name),
            &repo_path
        )?;
    }
    
    let readme_full_path = repo_path.join(&args.readme_path);
    fs::write(&readme_full_path, content)?;
    
    let repo = Repository::open(&repo_path)?;
    let mut index = repo.index()?;
    index.add_path(Path::new(&args.readme_path))?;
    index.write()?;
    
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let parent_commit = repo.head()?.peel_to_commit()?;
    let signature = git2::Signature::now("GitHub Stats Bot", "bot@example.com")?;
    
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Update code statistics",
        &tree,
        &[&parent_commit],
    )?;
    
    let mut remote = repo.find_remote("origin")?;
    let push_url = format!("https://{}@github.com/{}/{}.git", 
        args.token, args.username, args.repo_name);
    
    remote.push(
        &["refs/heads/main:refs/heads/main"],
        Some(git2::PushOptions::new().remote_callbacks(
            git2::RemoteCallbacks::new().credentials(|_, _, _| {
                git2::Cred::userpass_plaintext(&args.token, "")
            })
        ))
    )?;
    
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
