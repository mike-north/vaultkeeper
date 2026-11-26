/** Tie the transport to the lifetime of the public body, its readers, and its clones. */

/** The hidden input branch and its exclusive reader until it closes or is split. */
interface IUpstreamBranch {
  readonly stream: ReadableStream<Uint8Array>
  readonly reader: ReadableStreamDefaultReader<Uint8Array>
}

/**
 * Owns the Fetch response while the detached stream can read from it. A
 * pending transport read holds only a weak reference to the public controller.
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

  /** Forward one chunk on demand without rooting the public stream from the transport. */
  pull(controllerRef: WeakRef<ReadableByteStreamController>): void {
    const upstream = this.upstream
    if (upstream === undefined || this.reading) {
      return
    }
    this.reading = true
    void upstream.reader
      .read()
      .then((result) => {
        this.reading = false
        const controller = controllerRef.deref()
        if (this.upstream === undefined || controller === undefined) {
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
          this.pull(controllerRef)
        }
      })
      .catch(async (error: unknown) => {
        if (this.upstream !== undefined) {
          // Forward transport errors and byte-controller errors through the
          // reader, including EOF in the middle of a typed-array element.
          controllerRef.deref()?.error(error)
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
 * Expose a demand-driven byte stream whose source never roots the public stream.
 * A live native tee or reader still keeps the public stream reachable.
 */
function createBody(source: DetachedBodySource): ReadableStream<Uint8Array> {
  const stream = new ReadableStream({
    type: 'bytes',
    // A pending pull promise would hold the public controller alive from the
    // transport. Track the in-flight read separately so the controller stays weak.
    pull(controller: ReadableByteStreamController): void {
      source.pull(new WeakRef(controller))
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

/** Clone an unused detached stream, leaving other streams and unusable bodies to native Fetch. */
export function cloneDetachedBody(
  stream: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> | undefined {
  const source = detachedSources.get(stream)
  if (source === undefined) {
    return undefined
  }
  try {
    // Fetch validates whether a stream is locked or disturbed without reading it.
    void new Response(stream)
  } catch (error) {
    if (!(error instanceof TypeError)) {
      throw error
    }
    return undefined
  }
  const copy = source.fork()
  return copy === undefined ? undefined : createBody(copy)
}
