#!/usr/bin/env bash
# Combine skills for Claude inside the container.
# Claude reads from .claude/skills, while generic skills live in .agents/skills.
# If both exist, .claude/skills has precedence. Only skills not already present
# in .claude/skills (compared by name) are copied from .agents/skills.
set -euo pipefail

combine_skills_for_dir() {
  local target_dir="${1:-.}"
  local claude_skills="$target_dir/.claude/skills"
  local agents_skills="$target_dir/.agents/skills"

  if [ ! -d "$agents_skills" ]; then
    return 0
  fi

  mkdir -p "$claude_skills" 2>/dev/null || true

  for item in "$agents_skills"/*; do
    [ -e "$item" ] || [ -L "$item" ] || continue
    local name
    name="$(basename "$item")"
    # Compare by name: only copy if not inside claude's folder
    if [ ! -e "$claude_skills/$name" ] && [ ! -L "$claude_skills/$name" ]; then
      cp -R "$item" "$claude_skills/" 2>/dev/null || true
    fi
  done
}

combine_all() {
  local specified="${1:-}"
  if [ -n "$specified" ]; then
    combine_skills_for_dir "$specified"
    return 0
  fi

  # 1. Combine in current working directory (e.g., active workspace)
  combine_skills_for_dir "."

  # 2. Combine in all project directories located in /sandbox
  if [ -d "/sandbox" ]; then
    combine_skills_for_dir "/sandbox"
    for project_dir in /sandbox/*; do
      if [ -d "$project_dir" ]; then
        combine_skills_for_dir "$project_dir"
      fi
    done
  fi

  # 3. Combine in user home directory if present
  if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
    combine_skills_for_dir "$HOME"
  fi
}

combine_all "$@"
