/** Tie the transport to the lifetime of the public body and its native tee branches. */

/**
 * Owns the Fetch response while the detached stream can read from it. A
 * pending transport read holds only a weak reference to the public controller.
 */
class DetachedBodySource {
  private reading = false
  private finished = false

  constructor(
    // Fetch can cancel an unread body if its response is collected.
    private transport: Response | undefined,
    private readonly reader: ReadableStreamDefaultReader<Uint8Array>,
  ) {}

  /** Forward one chunk on demand without rooting the public stream from the transport. */
  pull(controllerRef: WeakRef<ReadableByteStreamController>): void {
    if (this.finished || this.reading) {
      return
    }
    this.reading = true
    void this.reader
      .read()
      .then((result) => {
        this.reading = false
        const controller = controllerRef.deref()
        if (this.finished || controller === undefined) {
          return
        }
        if (result.done) {
          controller.close()
          controller.byobRequest?.respond(0)
          this.finish()
        } else if (result.value.byteLength !== 0) {
          // The byte stream transfers the buffer on enqueue. The source can
          // share its chunk's backing buffer with other views.
          controller.enqueue(Uint8Array.from(result.value))
        } else {
          this.pull(controllerRef)
        }
      })
      .catch(async (error: unknown) => {
        if (!this.finished) {
          // Forward transport errors and byte-controller errors through the
          // reader, including EOF in the middle of a typed-array element.
          controllerRef.deref()?.error(error)
          await this.cancel(error).catch(() => undefined)
        }
      })
  }

  /** Cancel the upstream read when callers explicitly cancel or abandon the body graph. */
  async cancel(reason?: unknown): Promise<void> {
    if (!this.finished) {
      const canceled = this.reader.cancel(reason)
      this.finish()
      await canceled
    }
  }

  /** Detach upstream ownership when no more bytes can be read. */
  private finish(): void {
    this.finished = true
    abandonedBodies.unregister(this)
    this.reader.releaseLock()
    this.transport = undefined
  }
}

/** Cancel only when the public stream graph, including any surviving readers, is unreachable. */
const abandonedBodies = new FinalizationRegistry<DetachedBodySource>((source) => {
  void source.cancel().catch(() => undefined)
})

/**
 * Connect a native Response body to an independent, demand-driven byte stream.
 * Native cloning keeps this stream reachable as long as a tee branch needs it.
 */
export function detachBody(
  transport: Response,
  body: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
  const source = new DetachedBodySource(transport, body.getReader())
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
  abandonedBodies.register(stream, source, source)
  return stream
}
