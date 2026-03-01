/**
 * Registry for secret backend implementations.
 *
 * @remarks
 * The registry maintains a mapping of backend types to factory functions,
 * allowing dynamic creation of backends based on configuration.
 */

import type { SecretBackend, BackendFactory } from './types.js'
import type { BackendSetupFactory } from './setup-types.js'
import { BackendUnavailableError } from '../errors.js'

/**
 * Registry for secret backend implementations.
 *
 * @remarks
 * The registry allows registration of custom backends and provides
 * a factory method to create backend instances from a type string.
 *
 * Note: This class is used as a namespace for static methods.
 * @public
 */
// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export class BackendRegistry {
  private static backends = new Map<string, BackendFactory>()
  private static setups = new Map<string, BackendSetupFactory>()

  /**
   * Register a backend factory.
   * @param type - Backend type identifier
   * @param factory - Factory function to create backend instances
   */
  static register(type: string, factory: BackendFactory): void {
    this.backends.set(type, factory)
  }

  /**
   * Create a backend instance by type.
   * @param type - Backend type identifier
   * @returns A SecretBackend instance
   * @throws {@link BackendUnavailableError} if the backend type is not registered
   */
  static create(type: string): SecretBackend {
    const factory = this.backends.get(type)
    if (factory === undefined) {
      throw new BackendUnavailableError(
        `Unknown backend type: ${type}. ` +
          `Available types: ${Array.from(this.backends.keys()).join(', ')}`,
        'unknown-type',
        Array.from(this.backends.keys()),
      )
    }
    return factory()
  }

  /**
   * Get all registered backend type identifiers.
   * @returns Array of backend type identifiers
   */
  static getTypes(): string[] {
    return Array.from(this.backends.keys())
  }

  /**
   * Returns backend types that are available on the current system.
   *
   * @remarks
   * Creates each registered backend via its factory, calls `isAvailable()`,
   * and returns only the type identifiers whose backend reports availability.
   * If a backend's `isAvailable()` call throws, that backend is excluded from
   * the result rather than propagating the error.
   *
   * @returns Promise resolving to an array of available backend type identifiers
   * @public
   */
  static async getAvailableTypes(): Promise<string[]> {
    const entries = Array.from(this.backends.entries())
    const results = await Promise.all(
      entries.map(async ([type, factory]) => {
        try {
          const backend = factory()
          const available = await backend.isAvailable()
          return available ? type : null
        } catch {
          return null
        }
      }),
    )
    return results.filter((type): type is string => type !== null)
  }

  /**
   * Register a setup factory for a backend type.
   * @param type - Backend type identifier
   * @param factory - Factory function that creates a setup generator
   */
  static registerSetup(type: string, factory: BackendSetupFactory): void {
    this.setups.set(type, factory)
  }

  /**
   * Get the setup factory for a backend type, if one is registered.
   * @param type - Backend type identifier
   * @returns The setup factory, or `undefined` if none is registered
   */
  static getSetup(type: string): BackendSetupFactory | undefined {
    return this.setups.get(type)
  }

  /**
   * Check whether a setup factory is registered for the given backend type.
   * @param type - Backend type identifier
   * @returns `true` if a setup factory is registered
   */
  static hasSetup(type: string): boolean {
    return this.setups.has(type)
  }

  /**
   * Clear all registered backend factories.
   * Intended for use in tests only.
   * @internal
   */
  static clearBackends(): void {
    this.backends.clear()
  }

  /**
   * Clear all registered setup factories.
   * Intended for use in tests only.
   * @internal
   */
  static clearSetups(): void {
    this.setups.clear()
  }
}
