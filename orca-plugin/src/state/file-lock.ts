import fs from 'node:fs'
import path from 'node:path'

const SLEEP_ARRAY = new Int32Array(new SharedArrayBuffer(4))

function sleepSync(ms: number): void {
  try {
    Atomics.wait(SLEEP_ARRAY, 0, 0, ms)
  } catch {
    const end = Date.now() + ms
    while (Date.now() < end) {
      // Fallback spin if Atomics.wait is unavailable in current thread
    }
  }
}

function isLockPidAlive(pid?: number): boolean {
  if (typeof pid !== 'number' || !Number.isFinite(pid) || pid <= 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

function isLockStale(lockDir: string, staleMs: number): boolean {
  try {
    const ownerFile = path.join(lockDir, 'owner.json')
    if (fs.existsSync(ownerFile)) {
      const parsed = JSON.parse(fs.readFileSync(ownerFile, 'utf8')) as {
        pid?: number
        createdAt?: number
      }
      if (parsed?.pid && !isLockPidAlive(parsed.pid)) {
        return true
      }
      if (typeof parsed?.createdAt === 'number' && Date.now() - parsed.createdAt > staleMs) {
        return true
      }
    }
    const stat = fs.statSync(lockDir)
    return Date.now() - stat.mtimeMs > staleMs
  } catch {
    return false
  }
}

/**
 * Executes `fn` while holding a cross-process atomic directory lock (`<targetFilePath>.lock`).
 * Automatically reclaims stale locks left behind by crashed processes via atomic rename-aside.
 */
export function withStateLock<T>(
  targetFilePath: string,
  fn: () => T,
  timeoutMs = 4000,
  staleMs = 30000
): T {
  const parentDir = path.dirname(targetFilePath)
  fs.mkdirSync(parentDir, { recursive: true })
  const lockDir = `${targetFilePath}.lock`
  const deadline = Date.now() + timeoutMs
  let acquired = false

  while (Date.now() < deadline) {
    try {
      fs.mkdirSync(lockDir)
      acquired = true
      try {
        fs.writeFileSync(
          path.join(lockDir, 'owner.json'),
          JSON.stringify({ pid: process.pid, createdAt: Date.now() }),
          'utf8'
        )
      } catch {}
      break
    } catch (err: any) {
      if (err?.code !== 'EEXIST') {
        break
      }
      if (isLockStale(lockDir, staleMs)) {
        const brokenDir = `${lockDir}.stale-${process.pid}-${Date.now()}`
        try {
          fs.renameSync(lockDir, brokenDir)
          fs.rmSync(brokenDir, { recursive: true, force: true })
          continue
        } catch {}
      }
      sleepSync(15)
    }
  }

  try {
    return fn()
  } finally {
    if (acquired) {
      try {
        fs.rmSync(lockDir, { recursive: true, force: true })
      } catch {}
    }
  }
}

/**
 * Safely reads and parses a JSON state file.
 * If the file contains corrupted JSON, moves it aside as `<filePath>.broken-<timestamp>`
 * and returns `fallback` so state mutations self-heal without losing forensic data.
 */
export function readJsonSafe<T>(filePath: string, fallback: T): T {
  try {
    if (!fs.existsSync(filePath)) return fallback
    const raw = fs.readFileSync(filePath, 'utf8')
    if (!raw.trim()) return fallback
    return JSON.parse(raw) as T
  } catch {
    try {
      if (fs.existsSync(filePath)) {
        const brokenPath = `${filePath}.broken-${Date.now()}`
        fs.renameSync(filePath, brokenPath)
      }
    } catch {}
    return fallback
  }
}

/**
 * Atomically writes JSON data to `filePath` via a PID-scoped temporary file and rename.
 */
export function writeJsonAtomic(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + '\n', 'utf8')
  fs.renameSync(tmpPath, filePath)
}
