import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { combineSkills } from './agents/claude.js';

describe('combineSkills', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'skills-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('preserves existing skills in .claude/skills and only copies missing skills from .agents/skills', () => {
    const claudeSkillA = path.join(tmpDir, '.claude', 'skills', 'skill-a');
    const claudeSkillB = path.join(tmpDir, '.claude', 'skills', 'skill-b');
    const agentsSkillB = path.join(tmpDir, '.agents', 'skills', 'skill-b');
    const agentsSkillC = path.join(tmpDir, '.agents', 'skills', 'skill-c');

    fs.mkdirSync(claudeSkillA, { recursive: true });
    fs.writeFileSync(path.join(claudeSkillA, 'SKILL.md'), 'claude version A');

    fs.mkdirSync(claudeSkillB, { recursive: true });
    fs.writeFileSync(path.join(claudeSkillB, 'SKILL.md'), 'claude version B');

    fs.mkdirSync(agentsSkillB, { recursive: true });
    fs.writeFileSync(path.join(agentsSkillB, 'SKILL.md'), 'agents version B');

    fs.mkdirSync(agentsSkillC, { recursive: true });
    fs.writeFileSync(path.join(agentsSkillC, 'SKILL.md'), 'agents version C');

    combineSkills(tmpDir);

    const claudeSkillsDir = path.join(tmpDir, '.claude', 'skills');
    const entries = fs.readdirSync(claudeSkillsDir).sort();
    expect(entries).toEqual(['skill-a', 'skill-b', 'skill-c']);

    // skill-a is untouched
    expect(fs.readFileSync(path.join(claudeSkillA, 'SKILL.md'), 'utf-8')).toBe('claude version A');
    // skill-b has precedence from .claude/skills
    expect(fs.readFileSync(path.join(claudeSkillB, 'SKILL.md'), 'utf-8')).toBe('claude version B');
    // skill-c is copied from .agents/skills
    expect(fs.readFileSync(path.join(claudeSkillsDir, 'skill-c', 'SKILL.md'), 'utf-8')).toBe('agents version C');
  });

  it('creates .claude/skills and copies all skills if .claude/skills did not exist', () => {
    const agentsSkill1 = path.join(tmpDir, '.agents', 'skills', 'beads');
    fs.mkdirSync(agentsSkill1, { recursive: true });
    fs.writeFileSync(path.join(agentsSkill1, 'SKILL.md'), 'beads skill');

    combineSkills(tmpDir);

    const claudeSkill = path.join(tmpDir, '.claude', 'skills', 'beads', 'SKILL.md');
    expect(fs.existsSync(claudeSkill)).toBe(true);
    expect(fs.readFileSync(claudeSkill, 'utf-8')).toBe('beads skill');
  });

  it('no-ops when .agents/skills does not exist', () => {
    combineSkills(tmpDir);
    expect(fs.existsSync(path.join(tmpDir, '.claude', 'skills'))).toBe(false);
  });
});
