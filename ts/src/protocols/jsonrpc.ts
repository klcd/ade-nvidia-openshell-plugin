import { Transform, type TransformCallback } from 'node:stream';

/**
 * JSON-RPC 2.0 message parser and bidirectional path translator for Orca Chat Mode.
 */

export function rewriteJsonRpcPaths(
  line: string,
  hostPrefix: string,
  containerPrefix: string,
  direction: 'hostToContainer' | 'containerToHost'
): string {
  try {
    const obj = JSON.parse(line);
    const src = direction === 'hostToContainer' ? hostPrefix : containerPrefix;
    const dst = direction === 'hostToContainer' ? containerPrefix : hostPrefix;

    function walk(val: unknown): void {
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (let i = 0; i < val.length; i++) {
            if (typeof val[i] === 'string' && (val[i] as string).includes(src)) {
              val[i] = (val[i] as string).replaceAll(src, dst);
            } else {
              walk(val[i]);
            }
          }
        } else {
          const record = val as Record<string, unknown>;
          for (const key of Object.keys(record)) {
            const v = record[key];
            if (typeof v === 'string' && v.includes(src)) {
              record[key] = v.replaceAll(src, dst);
            } else {
              walk(v);
            }
          }
        }
      }
    }

    walk(obj);
    return JSON.stringify(obj);
  } catch {
    return line;
  }
}

export function isTurnCompleteFrame(line: string): boolean {
  try {
    const obj = JSON.parse(line) as { type?: unknown; method?: unknown };
    return obj?.type === 'result' || obj?.method === 'turn/completed';
  } catch {
    return false;
  }
}

/** Rewrite complete NDJSON frames while preserving streaming backpressure. */
export function createJsonRpcPathTransform(
  hostPrefix: string,
  containerPrefix: string,
  direction: 'hostToContainer' | 'containerToHost',
  onTurnComplete?: () => Promise<void> | void
): Transform {
  let pending = Buffer.alloc(0);
  const rewriteFrame = async (frame: Buffer): Promise<Buffer> => {
    const line = frame.toString('utf8').replace(/\r$/, '');
    if (direction === 'containerToHost' && onTurnComplete && isTurnCompleteFrame(line)) {
      try {
        await onTurnComplete();
      } catch {
        // Never interrupt the protocol stream if a turn sync fails
      }
    }
    return Buffer.from(`${rewriteJsonRpcPaths(line, hostPrefix, containerPrefix, direction)}\n`, 'utf8');
  };

  return new Transform({
    transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) {
      void (async () => {
        pending = Buffer.concat([pending, chunk]);
        let newline: number;
        while ((newline = pending.indexOf(0x0a)) !== -1) {
          const rawFrame = pending.subarray(0, newline);
          pending = pending.subarray(newline + 1);
          this.push(await rewriteFrame(rawFrame));
        }
        callback();
      })().catch(err => callback(err as Error));
    },
    flush(callback: TransformCallback) {
      void (async () => {
        if (pending.length > 0) {
          this.push(await rewriteFrame(pending));
          pending = Buffer.alloc(0);
        }
        callback();
      })().catch(err => callback(err as Error));
    },
  });
}
