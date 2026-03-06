/* tslint:disable */
/* eslint-disable */

/**
 * WASM-exposed VaultKeeper wrapper.
 */
export class WasmVaultKeeper {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt a JWE token, validate its claims, and return { claims, response }.
     */
    authorize(jwe: string): any;
    /**
     * Get the current configuration as JSON.
     */
    config(): any;
    /**
     * Delete a secret via the file backend.
     */
    delete(id: string): Promise<void>;
    /**
     * Run doctor checks and return a PreflightResult as JSON.
     */
    doctor(): Promise<any>;
    /**
     * Retrieve a secret via the file backend.
     */
    retrieve(id: string): Promise<string>;
    /**
     * Rotate the encryption key.
     */
    rotateKey(): void;
    /**
     * Create a JWE token encapsulating a secret.
     */
    setup(secret_name: string, secret_value: string, options: any): string;
    /**
     * Store a secret via the file backend.
     */
    store(id: string, secret: string): Promise<void>;
}

/**
 * Factory function to create a WasmVaultKeeper.
 */
export function createVaultKeeper(host: any, options: any): Promise<WasmVaultKeeper>;

/**
 * Initialize the WASM module. Called once on load.
 */
export function init(): void;
