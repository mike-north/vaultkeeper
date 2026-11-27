import { PassThrough } from 'node:stream'
import { StringDecoder } from 'node:string_decoder'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { collectUtf8 } from '../../../src/util/collect-utf8.js'

afterEach(() => vi.restoreAllMocks())

describe('subprocess UTF-8 collection', () => {
  it('matches UTF-8 replacement semantics across chunk boundaries', () => {
    const examples = [
      [0x61, 0xf0, 0x9f, 0x94, 0x90, 0x62],
      [0xe0, 0x80, 0xc2, 0xa2],
      [0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80],
      [0xe2, 0x82, 0x41, 0xf0, 0x9f],
    ]
    for (const example of examples) {
      for (let split = 0; split <= example.length; split++) {
        const stream = new PassThrough()
        const collector = collectUtf8(stream)
        stream.write(Buffer.from(example.slice(0, split)))
        stream.write(Buffer.from(example.slice(split)))
        expect(collector.finish()).toBe(Buffer.from(example).toString('utf8'))
      }
    }
  })

  it.each(['finish', 'incomplete', 'discard'])('wipes decoder storage on %s', (outcome) => {
    const retained: Uint8Array[] = []
    const original: unknown = Reflect.get(StringDecoder.prototype, 'write')
    if (typeof original !== 'function') throw new TypeError('Missing decoder write method')
    vi.spyOn(StringDecoder.prototype, 'write').mockImplementation(function (input) {
      const result: unknown = Reflect.apply(original, this, [input])
      if (typeof result !== 'string') throw new TypeError('Invalid decoder result')
      for (const symbol of Object.getOwnPropertySymbols(this)) {
        const value: unknown = Reflect.get(this, symbol)
        if (value instanceof Uint8Array) retained.push(value)
      }
      return result
    })
    const stream = new PassThrough()
    const allocate = Buffer.alloc.bind(Buffer)
    vi.spyOn(Buffer, 'alloc').mockImplementation((size, fill, encoding) => {
      const buffer = allocate(size, fill, encoding)
      retained.push(buffer)
      return buffer
    })
    const collector = collectUtf8(stream)
    const first = Buffer.from([0xf0, 0x9f])
    stream.write(first)
    expect([...first]).toEqual([0, 0])
    if (outcome === 'finish') {
      const second = Buffer.from([0x94, 0x90])
      stream.write(second)
      expect(collector.finish()).toBe('🔐')
      expect([...second]).toEqual([0, 0])
    } else if (outcome === 'incomplete') {
      expect(collector.finish()).toBe('�')
    } else {
      collector.discard()
      for (const bytes of retained) expect([...bytes]).toEqual(Array.from(bytes, () => 0))
      const late = Buffer.from([0x94, 0x90])
      stream.write(late)
      expect([...late]).toEqual([0, 0])
      expect(collector.finish()).toBe('')
    }
    expect(retained.length).toBeGreaterThan(0)
    for (const bytes of retained) expect([...bytes]).toEqual(Array.from(bytes, () => 0))
  })
})
