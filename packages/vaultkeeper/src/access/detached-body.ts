/** Tie the transport to the lifetime of the public body, its readers, and its clones. */

/** The hidden input branch and its exclusive reader until it closes or is split. */
interface IUpstreamBranch {
  readonly stream: ReadableStream<Uint8Array>
  readonly reader: ReadableStreamDefaultReader<Uint8Array>
}

/**
 * Owns the Fetch response while the detached stream can read from it. An
 * outstanding byte request owns its public controller until data or EOF arrives.
 */
class DetachedBodySource {
  private reading = false
  private upstream: IUpstreamBranch | undefined

  constructor(
    // Fetch can cancel an unread body if its response is collected.
    private transport: Response | undefined,
    stream: ReadableStream<Uint8Array>,
  ) {
    this.upstream = { stream, reader: stream.getReader() }
  }

  /** Split the hidden input so each public branch has an independent lifetime. */
  fork(): DetachedBodySource | undefined {
    const upstream = this.upstream
    if (upstream === undefined) {
      return undefined
    }
    upstream.reader.releaseLock()
    const [original, copy] = upstream.stream.tee()
    this.upstream = { stream: original, reader: original.getReader() }
    return new DetachedBodySource(this.transport, copy)
  }

  /** Forward one chunk on demand, keeping the pending read's stream alive. */
  pull(controller: ReadableByteStreamController): void {
    const upstream = this.upstream
    if (upstream === undefined || this.reading) {
      return
    }
    this.reading = true
    void upstream.reader
      .read()
      .then((result) => {
        this.reading = false
        if (this.upstream === undefined) {
          return
        }
        if (result.done) {
          controller.close()
          controller.byobRequest?.respond(0)
          this.finish(upstream.reader)
        } else if (result.value.byteLength !== 0) {
          // The byte stream transfers the buffer on enqueue. The source can
          // share its chunk's backing buffer with other views.
          controller.enqueue(Uint8Array.from(result.value))
        } else {
          this.pull(controller)
        }
      })
      .catch(async (error: unknown) => {
        if (this.upstream !== undefined) {
          // Forward transport errors and byte-controller errors through the
          // reader, including EOF in the middle of a typed-array element.
          controller.error(error)
          await this.cancel(error).catch(() => undefined)
        }
      })
  }

  /** Cancel the upstream read when callers explicitly cancel or abandon the body graph. */
  async cancel(reason?: unknown): Promise<void> {
    if (this.upstream !== undefined) {
      const { reader } = this.upstream
      const canceled = reader.cancel(reason)
      this.finish(reader)
      await canceled
    }
  }

  /** Detach upstream ownership when no more bytes can be read. */
  private finish(reader: ReadableStreamDefaultReader<Uint8Array>): void {
    this.upstream = undefined
    abandonedBodies.unregister(this)
    reader.releaseLock()
    this.transport = undefined
  }
}

/** Cancel only when the public stream graph, including any surviving readers, is unreachable. */
const abandonedBodies = new FinalizationRegistry<DetachedBodySource>((source) => {
  void source.cancel().catch(() => undefined)
})

/** Look up the source only for streams owned by this module. */
const detachedSources = new WeakMap<ReadableStream<Uint8Array>, DetachedBodySource>()

/**
 * Expose a byte stream with zero default buffering. Idle streams can be
 * collected. Once a read starts, its promise can outlive the stream and reader
 * references held by the caller, so the upstream read keeps the controller alive.
 */
function createBody(source: DetachedBodySource): ReadableStream<Uint8Array> {
  const stream = new ReadableStream({
    type: 'bytes',
    pull(controller: ReadableByteStreamController): void {
      source.pull(controller)
    },
    cancel(reason: unknown): Promise<void> {
      return source.cancel(reason)
    },
  })
  detachedSources.set(stream, source)
  abandonedBodies.register(stream, source, source)
  return stream
}

/** Separate a transport body from response metadata while retaining the upstream response for reads. */
export function detachBody(
  transport: Response,
  body: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
  return createBody(new DetachedBodySource(transport, body))
}

/** Split an owned input and retire the previous public stream's source association. */
function forkDetachedBody(
  previousBody: ReadableStream<Uint8Array>,
): { source: DetachedBodySource; copy: ReadableStream<Uint8Array> } | undefined {
  const source = detachedSources.get(previousBody)
  const copy = source?.fork()
  if (source === undefined || copy === undefined) {
    return undefined
  }
  detachedSources.delete(previousBody)
  return { source, copy: createBody(copy) }
}

/** Give the ordinary clone its own input after native Fetch has moved the original body. */
export function splitDetachedBody(
  previousBody: ReadableStream<Uint8Array>,
  original: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> | undefined {
  const branches = forkDetachedBody(previousBody)
  if (branches === undefined) {
    return undefined
  }
  detachedSources.set(original, branches.source)
  return branches.copy
}

/** Replace an unused body without invoking older Fetch implementations' native tee. */
export function replaceDetachedBody(
  previousBody: ReadableStream<Uint8Array>,
): { original: ReadableStream<Uint8Array>; copy: ReadableStream<Uint8Array> } | undefined {
  const branches = forkDetachedBody(previousBody)
  if (branches === undefined) {
    return undefined
  }
  // Keep any pre-clone body reference locked. Only the new original stream
  // owns its upstream lifetime after the response switches to it.
  previousBody.getReader()
  abandonedBodies.unregister(branches.source)
  return { original: createBody(branches.source), copy: branches.copy }
}
